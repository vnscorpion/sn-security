//! Parse `/proc/net/tcp` and `/proc/net/tcp6` without calling `ss`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ST_ESTABLISHED: u8 = 0x01;
pub const ST_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "local address retained for diagnostics/future status output"
)]
pub struct Conn {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}

fn parse_v4_hex(s: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = s.split_once(':')?;
    // The kernel prints the 32-bit address as a host-order hex word; its
    // little-endian byte layout is the dotted-quad in order (e.g. 0100007F ->
    // [0x7F,0,0,1] = 127.0.0.1).
    let raw = u32::from_str_radix(ip, 16).ok()?;
    let addr = Ipv4Addr::from(raw.to_le_bytes());
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V4(addr), port))
}

fn parse_v6_hex(s: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = s.split_once(':')?;
    if ip.len() != 32 {
        return None;
    }
    // Four host-order 32-bit words; each word's little-endian bytes are the
    // next four address bytes in order.
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
}

fn parse_file(path: &str, v6: bool) -> Vec<Conn> {
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(path) else {
        return out;
    };
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let parse = if v6 { parse_v6_hex } else { parse_v4_hex };
        let Some((local, local_port)) = parse(f[1]) else {
            continue;
        };
        let Some((remote, remote_port)) = parse(f[2]) else {
            continue;
        };
        let Ok(state) = u8::from_str_radix(f[3], 16) else {
            continue;
        };
        let inode: u64 = f[9].parse().unwrap_or(0);
        out.push(Conn {
            local,
            local_port,
            remote,
            remote_port,
            state,
            inode,
        });
    }
    out
}

/// All TCP connections across v4 and v6.
pub fn all() -> Vec<Conn> {
    let mut v = parse_file("/proc/net/tcp", false);
    v.extend(parse_file("/proc/net/tcp6", true));
    v
}

/// Map socket inode -> connection, for correlating a process's fds.
pub fn by_inode(conns: &[Conn]) -> HashMap<u64, Conn> {
    conns
        .iter()
        .filter(|c| c.inode != 0)
        .map(|c| (c.inode, c.clone()))
        .collect()
}

/// What listens locally, to tell a connection a local server accepted from one
/// this host opened. The remote port of an accepted connection is whatever the
/// client chose, so it says nothing about where the server process connects.
#[derive(Debug, Default)]
pub struct Listeners {
    /// Ports listened on every address (`0.0.0.0`, `::`).
    any: HashSet<u16>,
    /// Ports listened on one address.
    exact: HashSet<(IpAddr, u16)>,
}

impl Listeners {
    pub fn new(conns: &[Conn]) -> Self {
        let mut l = Listeners::default();
        for c in conns.iter().filter(|c| c.state == ST_LISTEN) {
            let local = snsec_common::net::normalize(c.local);
            if local.is_unspecified() {
                l.any.insert(c.local_port);
            } else {
                l.exact.insert((local, c.local_port));
            }
        }
        l
    }

    /// Was `c` accepted by a local listener (its local end is a listening port)?
    #[must_use]
    pub fn accepted(&self, c: &Conn) -> bool {
        self.any.contains(&c.local_port)
            || self
                .exact
                .contains(&(snsec_common::net::normalize(c.local), c.local_port))
    }

    /// Is `c` an ESTABLISHED connection this host opened to a non-loopback peer?
    #[must_use]
    pub fn outbound(&self, c: &Conn) -> bool {
        c.state == ST_ESTABLISHED
            && !snsec_common::net::normalize(c.remote).is_loopback()
            && !self.accepted(c)
    }
}

/// TCP ports currently in LISTEN state (both families).
pub fn listening_ports(conns: &[Conn]) -> Vec<u16> {
    let mut p: Vec<u16> = conns
        .iter()
        .filter(|c| c.state == ST_LISTEN)
        .map(|c| c.local_port)
        .collect();
    p.sort_unstable();
    p.dedup();
    p
}

/// Remote peers of ESTABLISHED connections whose local port is in `ports`
/// (e.g. active SSH or panel sessions), normalized to plain IPs.
pub fn established_peers_on(conns: &[Conn], ports: &[u16]) -> Vec<IpAddr> {
    conns
        .iter()
        .filter(|c| c.state == ST_ESTABLISHED && ports.contains(&c.local_port))
        .map(|c| snsec_common::net::normalize(c.remote))
        .collect()
}

/// Count open connections per remote IP (slowloris / flood signal).
pub fn conns_per_remote(conns: &[Conn]) -> HashMap<String, u32> {
    let mut m = HashMap::new();
    for c in conns.iter().filter(|c| c.state == ST_ESTABLISHED) {
        if c.remote.is_loopback() {
            continue;
        }
        *m.entry(snsec_common::net::ban_key(c.remote)).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(local: &str, lport: u16, remote: &str, rport: u16, state: u8) -> Conn {
        Conn {
            local: local.parse().unwrap(),
            local_port: lport,
            remote: remote.parse().unwrap(),
            remote_port: rport,
            state,
            inode: 0,
        }
    }

    #[test]
    fn a_client_connecting_from_a_pool_port_is_inbound_not_outbound() {
        let conns = vec![
            conn("0.0.0.0", 443, "0.0.0.0", 0, ST_LISTEN),
            conn("::", 8080, "::", 0, ST_LISTEN),
            conn("10.0.0.5", 2222, "0.0.0.0", 0, ST_LISTEN),
            conn("127.0.0.1", 6379, "0.0.0.0", 0, ST_LISTEN),
        ];
        let l = Listeners::new(&conns);
        // Clients that picked port 4444 as their source port.
        for c in [
            conn("10.0.0.5", 443, "198.51.100.7", 4444, ST_ESTABLISHED),
            conn(
                "::ffff:10.0.0.5",
                8080,
                "::ffff:198.51.100.7",
                4444,
                ST_ESTABLISHED,
            ),
            conn("2001:db8::5", 8080, "2001:db8::9", 4444, ST_ESTABLISHED),
            conn("10.0.0.5", 2222, "198.51.100.7", 4444, ST_ESTABLISHED),
        ] {
            assert!(l.accepted(&c) && !l.outbound(&c), "{c:?}");
        }
        // This host connecting out to a pool.
        let out = conn("10.0.0.5", 51234, "198.51.100.7", 4444, ST_ESTABLISHED);
        assert!(!l.accepted(&out) && l.outbound(&out));
        // Port 2222 is only listened on 10.0.0.5: the same port on another address
        // is a connection this host opened.
        let other = conn("10.0.0.6", 2222, "198.51.100.7", 4444, ST_ESTABLISHED);
        assert!(l.outbound(&other));
        // Loopback peers and sockets that are not established are never outbound.
        assert!(!l.outbound(&conn("127.0.0.1", 40000, "127.0.0.1", 4444, ST_ESTABLISHED)));
        assert!(!l.outbound(&conn(
            "::ffff:127.0.0.1",
            40000,
            "::ffff:127.0.0.1",
            4444,
            ST_ESTABLISHED
        )));
        assert!(!l.outbound(&conn("10.0.0.5", 51234, "198.51.100.7", 4444, 0x06)));
    }
}

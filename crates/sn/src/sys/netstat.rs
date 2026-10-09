//! Parse `/proc/net/tcp` and `/proc/net/tcp6` without calling `ss`.

use std::collections::HashMap;
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

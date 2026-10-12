//! Self-lockout protection: the set of addresses `sn` must never ban.
//!
//! This is the agent's single most important safety property (plan §7, review
//! LNX-1/SEC-6). It covers: loopback, every local interface address, the hub,
//! the admin ranges from config, *active* SSH/panel sessions (resolved from the
//! real listening ports, including IPv6-mapped sessions on dual-stack sockets),
//! and any IP that logged in over SSH successfully in the recent past.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, ToSocketAddrs};

use snsec_common::net::{self, Cidr};

use crate::config::Config;
use crate::evidence_parse;
use crate::sys::{netstat, proc};

/// Ports on which an established peer is treated as an admin and whitelisted,
/// when the port is actually listening locally.
const ADMIN_PORTS: &[u16] = &[
    22, 2222, 22022, // ssh (common alternates)
    21, 989, 990, // ftp/ftps
    2083, 2087, 2096, 2095, // cPanel
    2222, // DirectAdmin (also ssh alt)
    7800, 8888, 8443,  // aaPanel
    8090,  // CyberPanel
    10000, // Webmin
];

#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    cidrs: Vec<Cidr>,
}

impl Whitelist {
    /// Would banning `ip` lock out something we must protect?
    #[must_use]
    pub fn protects(&self, ip: IpAddr) -> bool {
        net::in_any(&self.cidrs, ip)
    }

    /// nft-ready keys (CIDR or plain address) for the `sn_white*` sets.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.cidrs
            .iter()
            .map(|c| {
                let max = if c.addr.is_ipv4() { 32 } else { 128 };
                if c.prefix == max {
                    c.addr.to_string()
                } else {
                    format!("{}/{}", c.addr, c.prefix)
                }
            })
            .collect()
    }

    fn push_ip(&mut self, ip: IpAddr) {
        let ip = net::normalize(ip);
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        self.cidrs.push(Cidr { addr: ip, prefix });
    }
}

/// Build the whitelist from config, the live socket table and the auth logs.
#[must_use]
pub fn build(cfg: &Config, conns: &[netstat::Conn]) -> Whitelist {
    let mut wl = Whitelist::default();

    // 1) loopback
    for c in ["127.0.0.0/8", "::1/128"] {
        if let Some(cidr) = Cidr::parse(c) {
            wl.cidrs.push(cidr);
        }
    }

    // 2) config admin ranges (local-only; never settable remotely)
    for c in &cfg.fw.whitelist {
        if let Some(cidr) = Cidr::parse(c) {
            wl.cidrs.push(cidr);
        }
    }

    // 3) every local interface address
    for ip in local_ips() {
        wl.push_ip(ip);
    }

    // 4) the hub
    for ip in resolve_hub(&cfg.hub.url) {
        wl.push_ip(ip);
    }

    // 5) active SSH/panel sessions
    for ip in admin_session_peers(conns) {
        wl.push_ip(ip);
    }

    // 6) recent successful SSH logins
    for ip in recent_ssh_logins() {
        wl.push_ip(ip);
    }

    wl
}

fn local_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifa in addrs {
            if let Some(sa) = ifa.address {
                if let Some(v4) = sa.as_sockaddr_in() {
                    out.push(IpAddr::V4(v4.ip()));
                } else if let Some(v6) = sa.as_sockaddr_in6() {
                    out.push(IpAddr::V6(v6.ip()));
                }
            }
        }
    }
    out
}

/// Listening ports owned by sshd, discovered via its socket inodes, merged
/// with the known admin-port list that is actually listening.
fn admin_listen_ports(conns: &[netstat::Conn]) -> BTreeSet<u16> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();

    // sshd's own listening ports (handles custom Port= and socket activation).
    let by_inode = netstat::by_inode(conns);
    for pid in proc::list_pids() {
        let st = match proc::read_stat(pid) {
            Some(s) => s,
            None => continue,
        };
        if st.comm == "sshd" || st.comm.starts_with("sshd") {
            for ino in proc::socket_inodes(pid) {
                if let Some(c) = by_inode.get(&ino)
                    && c.state == netstat::ST_LISTEN
                {
                    ports.insert(c.local_port);
                }
            }
        }
    }
    ports.insert(22); // always protect the default

    // Known admin/panel ports that are currently listening.
    let listening = netstat::listening_ports(conns);
    for p in ADMIN_PORTS {
        if listening.contains(p) {
            ports.insert(*p);
        }
    }
    ports
}

fn admin_session_peers(conns: &[netstat::Conn]) -> Vec<IpAddr> {
    let ports: Vec<u16> = admin_listen_ports(conns).into_iter().collect();
    netstat::established_peers_on(conns, &ports)
}

/// Parse the SSH host from `https://host:port` and resolve it to IPs.
fn resolve_hub(url: &str) -> Vec<IpAddr> {
    if url.is_empty() {
        return Vec::new();
    }
    let rest = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(443)),
        None => (host_port, 443),
    };
    match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Most addresses the auth logs may add, newest first. Any local program can
/// write a line tagged `sshd` to syslog, so the log must not be able to grow the
/// whitelist without limit; this is still far more than one admin's logins.
const MAX_LOG_LOGINS: usize = 64;

/// Addresses of recent successful SSH logins in the tail of the auth logs.
fn recent_ssh_logins() -> Vec<IpAddr> {
    let texts: Vec<String> = ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .filter_map(|p| read_tail(p, 512 * 1024))
        .collect();
    login_addrs(texts.iter().map(String::as_str))
}

/// The distinct addresses of successful logins, newest first, at most
/// `MAX_LOG_LOGINS`. Only a line sshd itself wrote as a success counts
/// (`evidence_parse::accepted_login`): sshd copies a client's chosen user name
/// into its failure lines, and that name must not be able to whitelist anyone.
fn login_addrs<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for text in texts {
        for line in text.lines().rev() {
            if out.len() >= MAX_LOG_LOGINS {
                return out;
            }
            if let Some((_, _, ip)) = evidence_parse::accepted_login(line) {
                let ip = net::normalize(ip);
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Read up to the last `max` bytes of a file as UTF-8 (lossy), from the first
/// whole line: a line cut at the start of the window could read as a different
/// line. Returns `None` if the file cannot be opened.
fn read_tail(path: &str, max: u64) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf).ok()?;
    if start > 0 {
        let first = buf
            .iter()
            .position(|&b| b == b'\n')
            .map_or(buf.len(), |i| i + 1);
        buf.drain(..first);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_user_name_that_spells_out_a_login_whitelists_nobody() {
        // sshd writes the name a client offered verbatim into its failure lines.
        let log = "Oct 12 02:00:00 h sshd[1]: Invalid user Accepted from 9.9.9.1 port 5\n\
                   Oct 12 02:00:01 h sshd[1]: Invalid user Accepted x from 6.6.6.6 from 9.9.9.2 port 5\n\
                   Oct 12 02:00:02 h sshd[1]: Invalid user x Accepted publickey for root from 1.2.3.4 from 9.9.9.3 port 5\n\
                   Oct 12 02:00:03 h sshd[1]: Failed password for invalid user Accepted password for admin from 9.9.9.4 port 22 ssh2 from 9.9.9.9 port 5 ssh2\n\
                   Oct 12 02:00:04 h sshd[1]: Failed password for invalid user x sshd[1]: Accepted password for a from 9.9.9.5 port 1 ssh2 from 9.9.9.9 port 5 ssh2\n\
                   Oct 12 02:00:05 h sshd[1]: Invalid user x: Accepted publickey for admin from 9.9.9.6 port 1 ssh2 from 9.9.9.9 port 5\n\
                   Oct 12 02:00:06 h vsftpd[3]: sshd[1]: Accepted password for a from 9.9.9.7 port 1 ssh2\n\
                   Oct 12 02:00:07 h sshd[1]: Connection closed by invalid user Accepted 9.9.9.8 port 5 [preauth]\n";
        assert!(login_addrs([log]).is_empty(), "{:?}", login_addrs([log]));
    }

    #[test]
    fn real_logins_are_whitelisted_newest_first_including_sshd_session() {
        let log = "Oct 12 02:00:00 h sshd[2]: Accepted publickey for ops from 203.0.113.7 port 50022 ssh2: ED25519 SHA256:k\n\
                   Oct 12 02:00:01 h sshd[1]: Invalid user Accepted from 9.9.9.1 port 5\n\
                   2026-10-12T02:00:02+07:00 h sshd-session[3]: Accepted password for dev from 2001:db8::7 port 1 ssh2\n\
                   Oct 12 02:00:03 h sshd[4]: Accepted password for ops from ::ffff:198.51.100.4 port 1 ssh2\n\
                   Oct 12 02:00:04 h sshd[5]: Accepted publickey for ops from 203.0.113.7 port 50023 ssh2\n";
        assert_eq!(
            login_addrs([log]),
            [ip("203.0.113.7"), ip("198.51.100.4"), ip("2001:db8::7")]
        );
    }

    #[test]
    fn the_log_adds_a_bounded_number_of_addresses_and_a_flood_of_one_cannot_push_out_another() {
        // More than the 30 the evidence keeps, all distinct: all of them stay.
        let some: String = (1..=40)
            .map(|i| {
                format!("Oct 12 02:00:00 h sshd[1]: Accepted password for u from 10.0.0.{i} port 1 ssh2\n")
            })
            .collect();
        assert_eq!(login_addrs([some.as_str()]).len(), 40);
        // Many more: only the newest MAX_LOG_LOGINS.
        let many: String = (1..=200)
            .map(|i| {
                format!("Oct 12 02:00:00 h sshd[1]: Accepted password for u from 10.0.1.{i} port 1 ssh2\n")
            })
            .collect();
        let got = login_addrs([many.as_str()]);
        assert_eq!(got.len(), MAX_LOG_LOGINS);
        assert_eq!(got[0], ip("10.0.1.200"));
        // The admin logged in once, then one address logged in a thousand times.
        let mut busy = String::from(
            "Oct 12 01:00:00 h sshd[1]: Accepted publickey for admin from 203.0.113.9 port 1 ssh2\n",
        );
        for _ in 0..1000 {
            busy.push_str(
                "Oct 12 02:00:00 h sshd[1]: Accepted password for app from 198.51.100.1 port 1 ssh2\n",
            );
        }
        assert_eq!(
            login_addrs([busy.as_str()]),
            [ip("198.51.100.1"), ip("203.0.113.9")]
        );
    }

    #[test]
    fn a_line_cut_by_the_tail_window_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.log");
        let whole =
            "Oct 12 02:00:01 h sshd[1]: Accepted password for a from 203.0.113.1 port 1 ssh2\n";
        // The window starts inside the first line, where what is left reads as a
        // line of its own.
        let first = "Oct 12 02:00:00 h sshd[1]: Invalid user 2026 h sshd[1]: Accepted password for a from 9.9.9.9 port 1 ssh2\n";
        std::fs::write(&path, format!("{first}{whole}")).unwrap();
        let cut = first.find("2026").unwrap();
        assert!(evidence_parse::accepted_login(&first[cut..first.len() - 1]).is_some());
        let max = (first.len() - cut + whole.len()) as u64;
        let text = read_tail(path.to_str().unwrap(), max).unwrap();
        assert_eq!(text, whole);
        assert_eq!(login_addrs([text.as_str()]), [ip("203.0.113.1")]);
        // A file that fits is read whole.
        let all = read_tail(path.to_str().unwrap(), 1 << 20).unwrap();
        assert_eq!(all, format!("{first}{whole}"));
    }
}

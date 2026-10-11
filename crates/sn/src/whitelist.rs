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

/// Scan the tail of the auth logs for `Accepted ... from <ip>` lines.
fn recent_ssh_logins() -> Vec<IpAddr> {
    let mut out = BTreeSet::new();
    for path in ["/var/log/auth.log", "/var/log/secure"] {
        if let Some(text) = read_tail(path, 512 * 1024) {
            for line in text.lines() {
                if line.contains("Accepted ")
                    && let Some(ip) = extract_after(line, " from ")
                    && let Ok(parsed) = ip.parse::<IpAddr>()
                {
                    out.insert(parsed);
                }
            }
        }
    }
    out.into_iter().collect()
}

fn extract_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let idx = line.find(marker)? + marker.len();
    line[idx..].split_whitespace().next()
}

/// Read up to the last `max` bytes of a file as UTF-8 (lossy). Returns `None`
/// if the file cannot be opened.
fn read_tail(path: &str, max: u64) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

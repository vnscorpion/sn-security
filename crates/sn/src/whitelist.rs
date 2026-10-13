//! Self-lockout protection: the set of addresses `sn` must never ban.
//!
//! This is the agent's single most important safety property (plan §7, review
//! LNX-1/SEC-6). It covers: loopback, the admin ranges from config, this
//! VPS's own addresses (every interface, and its public address as the hub
//! sees it: on a cloud that NATs it, that one is on no interface), the hub,
//! SSH sessions that logged in (open now or in the last half hour, resolved
//! from sshd's real listening ports, IPv6-mapped sessions on dual-stack
//! sockets included) and recent successful SSH logins from the auth logs.
//!
//! An SSH admin's IPv6 entry covers its whole /64: the other devices of that
//! LAN (the admin's browser with a privacy address) share its ban key. The
//! VPS's and the hub's own addresses stay exact, and their own requests are
//! not counted at all: on clouds that carve one /64 into many servers, the
//! rest of that /64 is other customers. Panel and FTP connections prove
//! nothing about who holds them (no login is needed to open one), so their
//! peers are only spared the volume rules, never whitelisted.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use snsec_common::net::{self, Cidr};

use crate::config::Config;
use crate::evidence_parse;
use crate::state::State;
use crate::sys::{netstat, proc};
use crate::util;

/// Ports on which an established peer is an admin session, when the port is
/// actually listening locally: SSH once sshd has let the user in, the others
/// (panels, FTP) only as session peers (see [`Whitelist`]).
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
    /// Loopback and the admin ranges from config: a ban key inside or around
    /// one is never banned, and the hub's bans of it are refused.
    ranges: Vec<Cidr>,
    /// SSH admins: IPv4 exactly, IPv6 as its /64. Never banned by this VPS's
    /// own rules; the firewall accepts them before any ban.
    admins: Vec<Cidr>,
    /// This VPS's own addresses and the hub's, exactly. Never banned, their
    /// requests not counted, and accepted by the firewall.
    own: Vec<IpAddr>,
    /// Peers of panel and FTP sessions open now, exactly. Only spared `rate`
    /// and `scanner`; not remembered, not in the firewall's whitelist.
    peers: Vec<IpAddr>,
}

impl Whitelist {
    /// Is `ip` itself whitelisted (as the firewall would accept it)?
    #[cfg(test)]
    #[must_use]
    pub fn protects(&self, ip: IpAddr) -> bool {
        net::in_any(&self.ranges, ip)
            || net::in_any(&self.admins, ip)
            || self.own.contains(&net::normalize(ip))
    }

    /// Must the ban key `net` (one address, or an IPv6 /64) never be banned by
    /// this VPS's own rules? When a configured range or an SSH admin's entry
    /// lies inside it or around it (checking only the first address the logs
    /// showed in a /64 would miss the admin's session two addresses further
    /// on), or when it is exactly one of the VPS's own addresses.
    #[must_use]
    pub fn protects_net(&self, net: Cidr) -> bool {
        self.ranges
            .iter()
            .chain(&self.admins)
            .any(|c| c.overlaps(&net))
            || self.own_key(net)
    }

    /// The key is one of the VPS's or the hub's own addresses. A /64 that
    /// merely holds one is not: the firewall accepts the address itself before
    /// any ban, and the rest of the /64 may be other customers' servers.
    fn own_key(&self, net: Cidr) -> bool {
        let max = if net.addr.is_ipv4() { 32 } else { 128 };
        net.prefix == max && self.own.iter().any(|ip| net.contains(*ip))
    }

    /// Must a ban the hub ordered for this key be refused here? For the
    /// configured ranges and the VPS's own addresses. An SSH session is no
    /// reason to refuse the operator (the firewall accepts it while it lasts
    /// anyway), and a panel or FTP connection proves nothing.
    #[must_use]
    pub fn refuses_hub_ban(&self, net: Cidr) -> bool {
        self.ranges.iter().any(|c| c.overlaps(&net)) || self.own_key(net)
    }

    /// Is the ban key a panel or FTP session's peer (that address, or the /64
    /// that holds it)?
    #[must_use]
    pub fn session_peer(&self, key: &str) -> bool {
        Cidr::parse(key).is_some_and(|net| self.peers.iter().any(|ip| net.contains(*ip)))
    }

    /// The VPS's and the hub's own addresses: their requests are not counted.
    #[must_use]
    pub fn own_addrs(&self) -> &[IpAddr] {
        &self.own
    }

    /// nft-ready keys for the `sn_white*` sets: the configured ranges, the SSH
    /// admins and the own addresses, plus `extra` (the trusted proxies),
    /// written so that no element holds another (an interval set refuses
    /// overlapping elements, and with them the whole update).
    #[must_use]
    pub fn keys(&self, extra: &[Cidr]) -> Vec<String> {
        let mut all: Vec<Cidr> = self.ranges.clone();
        all.extend_from_slice(&self.admins);
        all.extend(self.own.iter().map(|ip| exact(*ip)));
        all.extend_from_slice(extra);
        cidr_keys(&net::minimal_cover(&all))
    }

    /// A whitelist of exactly these configured ranges (tests elsewhere in the
    /// agent).
    #[cfg(test)]
    #[must_use]
    pub fn of(ranges: Vec<Cidr>) -> Whitelist {
        Whitelist {
            ranges,
            ..Whitelist::default()
        }
    }

    /// This VPS's (or the hub's) own address.
    fn push_own(&mut self, ip: IpAddr) {
        let ip = net::normalize(ip);
        if !self.own.contains(&ip) {
            self.own.push(ip);
        }
    }

    /// An SSH admin's address: IPv4 exactly, IPv6 as its /64, which is the
    /// unit the agent bans IPv6 by. Loopback and link-local addresses stay
    /// exact (`::1` must never become `::/64`).
    fn push_admin(&mut self, ip: IpAddr) {
        let ip = net::normalize(ip);
        let c = match ip {
            IpAddr::V6(v6) if !special_v6(v6) => Cidr {
                addr: IpAddr::V6(net64(v6)),
                prefix: 64,
            },
            _ => exact(ip),
        };
        self.admins.push(c);
    }

    /// A panel or FTP session's peer.
    fn push_peer(&mut self, ip: IpAddr) {
        let ip = net::normalize(ip);
        if !self.peers.contains(&ip) {
            self.peers.push(ip);
        }
    }
}

/// One address as a range of one (/32 or /128).
fn exact(ip: IpAddr) -> Cidr {
    let ip = net::normalize(ip);
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    Cidr { addr: ip, prefix }
}

/// Loopback, unspecified or link-local: never widened to a /64.
fn special_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// The network address of the /64 that holds `v6`.
fn net64(v6: Ipv6Addr) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&v6.octets()[..8]);
    Ipv6Addr::from(o)
}

/// nft-ready keys (CIDR or plain address, host bits cleared) for ranges.
#[must_use]
pub fn cidr_keys(cidrs: &[Cidr]) -> Vec<String> {
    cidrs
        .iter()
        .map(|c| {
            let c = c.canonical();
            let max = if c.addr.is_ipv4() { 32 } else { 128 };
            if c.prefix == max {
                c.addr.to_string()
            } else {
                format!("{}/{}", c.addr, c.prefix)
            }
        })
        .collect()
}

/// Must the ban key (`203.0.113.7`, or an IPv6 `2001:db8:1:2::/64`) never be
/// banned? It is when the whitelist protects it (see
/// [`Whitelist::protects_net`]), or it holds or lies in a range of `never_ban`
/// (the trusted proxies, Cloudflare). A key that is not an address is not
/// protected (and never reaches the firewall either).
#[must_use]
pub fn key_protected(key: &str, wl: &Whitelist, never_ban: &[Cidr]) -> bool {
    let Some(net) = Cidr::parse(key) else {
        return false;
    };
    wl.protects_net(net) || never_ban.iter().any(|c| c.overlaps(&net))
}

/// How long an SSH session's peer stays whitelisted after it was last seen
/// open: an admin who reconnects, or whose browser keeps working on the sites
/// after the shell closed, must not be treated as a visitor in between.
const ADMIN_MEMORY_SECS: i64 = 30 * 60;
/// Most remembered admin peers.
const MAX_REMEMBERED_ADMINS: usize = 256;

/// Fold the admin peers seen now into the remembered ones (`addr -> last seen`),
/// drop those not seen for [`ADMIN_MEMORY_SECS`], keep at most
/// [`MAX_REMEMBERED_ADMINS`] (the most recent), and return what is remembered.
fn remember_admins(known: &mut HashMap<String, i64>, seen_now: &[IpAddr], now: i64) -> Vec<IpAddr> {
    for ip in seen_now {
        known.insert(net::normalize(*ip).to_string(), now);
    }
    known.retain(|_, at| now - *at <= ADMIN_MEMORY_SECS && *at <= now + 60);
    if known.len() > MAX_REMEMBERED_ADMINS {
        let mut by_age: Vec<(i64, String)> = known.iter().map(|(k, at)| (*at, k.clone())).collect();
        by_age.sort_unstable_by(|a, b| b.cmp(a));
        for (_, k) in by_age.into_iter().skip(MAX_REMEMBERED_ADMINS) {
            known.remove(&k);
        }
    }
    known.keys().filter_map(|k| k.parse().ok()).collect()
}

/// Build the whitelist from config, the live socket table and the auth logs,
/// plus, with the agent's `state`, the SSH sessions of the last half hour
/// (remembered there) and the VPS's own public address as the hub saw it.
#[must_use]
pub fn build(cfg: &Config, conns: &[netstat::Conn], state: Option<&State>) -> Whitelist {
    let mut wl = Whitelist::default();

    // 1) loopback
    for c in ["127.0.0.0/8", "::1/128"] {
        if let Some(cidr) = Cidr::parse(c) {
            wl.ranges.push(cidr);
        }
    }

    // 2) config admin ranges (local-only; never settable remotely)
    for c in &cfg.fw.whitelist {
        if let Some(cidr) = Cidr::parse(c) {
            wl.ranges.push(cidr);
        }
    }

    // 3) every local interface address (loopback is in 1)
    for ip in local_ips() {
        if !net::normalize(ip).is_loopback() {
            wl.push_own(ip);
        }
    }

    // 4) the hub
    for ip in resolve_hub(&cfg.hub.url) {
        wl.push_own(ip);
    }

    // 5) SSH sessions open now and (with state) those of the last half hour;
    // panel and FTP sessions open now
    let live = admin_session_peers(conns);
    for ip in &live.ssh {
        wl.push_admin(*ip);
    }
    for ip in &live.other {
        wl.push_peer(*ip);
    }
    if let Some(state) = state {
        let mut known = state.recent_admins();
        let before = known.clone();
        for ip in remember_admins(&mut known, &live.ssh, util::now_secs()) {
            wl.push_admin(ip);
        }
        if known != before
            && let Err(e) = state.save_recent_admins(&known)
        {
            eprintln!("whitelist: could not remember admin sessions: {e:#}");
        }
        // 7) the VPS's own public address(es), as the hub saw it reach it
        for ip in state.meta().self_ips.iter().filter_map(|s| s.parse().ok()) {
            wl.push_own(ip);
        }
    }

    // 6) recent successful SSH logins
    for ip in recent_ssh_logins() {
        wl.push_admin(ip);
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

/// What the socket table and sshd's own processes say about admin sessions.
#[derive(Debug, Default)]
struct Sessions {
    /// Ports sshd listens on (custom `Port=` and socket activation included).
    sshd_ports: BTreeSet<u16>,
    /// Sockets held by an sshd process that has let its user in.
    logged_in: HashSet<u64>,
    /// The other admin and panel ports that are listening (22 too when sshd is
    /// not what listens there).
    other_ports: BTreeSet<u16>,
}

fn sessions(conns: &[netstat::Conn]) -> Sessions {
    let mut s = Sessions::default();
    let by_inode = netstat::by_inode(conns);
    for pid in proc::list_pids() {
        let Some(st) = proc::read_stat(pid) else {
            continue;
        };
        if !st.comm.starts_with("sshd") {
            continue;
        }
        let inodes = proc::socket_inodes(pid);
        for ino in &inodes {
            if let Some(c) = by_inode.get(ino)
                && c.state == netstat::ST_LISTEN
            {
                s.sshd_ports.insert(c.local_port);
            }
        }
        if proc::cmdline(pid)
            .first()
            .is_some_and(|t| logged_in_title(t))
        {
            s.logged_in.extend(inodes);
        }
    }
    // Known admin/panel ports that are listening, and always the default.
    let listening = netstat::listening_ports(conns);
    for &p in std::iter::once(&22).chain(ADMIN_PORTS) {
        if (p == 22 || listening.contains(&p)) && !s.sshd_ports.contains(&p) {
            s.other_ports.insert(p);
        }
    }
    s
}

/// Has the sshd process with this title let its user in? After a login sshd
/// calls itself `sshd: <user>` or `sshd: <user>@<tty>` (`sshd-session:` from
/// OpenSSH 9.8 on). Before, it is `[accepted]`, `<user> [priv]` or `<user> [net]`
/// with a name the client chose; the listener is `... [listener] ...`.
fn logged_in_title(title: &str) -> bool {
    let Some(who) = title
        .strip_prefix("sshd: ")
        .or_else(|| title.strip_prefix("sshd-session: "))
    else {
        return false;
    };
    let who = who.trim_end();
    !who.is_empty() && !who.contains([' ', '[', ']'])
}

/// Peers of live admin sessions.
#[derive(Debug, Default, PartialEq, Eq)]
struct Live {
    /// On sshd's ports, connections sshd has let a user in on: one kept open
    /// before login (reconnecting within LoginGraceTime) buys nothing.
    ssh: Vec<IpAddr>,
    /// On the panel and FTP ports: anyone can open one without logging in
    /// (FTP greets first), so these are only session peers.
    other: Vec<IpAddr>,
}

fn session_peers(conns: &[netstat::Conn], s: &Sessions) -> Live {
    let mut live = Live::default();
    for c in conns.iter().filter(|c| c.state == netstat::ST_ESTABLISHED) {
        let peer = net::normalize(c.remote);
        if s.sshd_ports.contains(&c.local_port) {
            if s.logged_in.contains(&c.inode) {
                live.ssh.push(peer);
            }
        } else if s.other_ports.contains(&c.local_port) {
            live.other.push(peer);
        }
    }
    live
}

fn admin_session_peers(conns: &[netstat::Conn]) -> Live {
    session_peers(conns, &sessions(conns))
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

/// Most addresses the logs may add, newest first. Any local program can write a
/// line tagged `sshd` to the text logs, so they must not be able to grow the
/// whitelist without limit; this is still far more than one admin's logins.
const MAX_LOG_LOGINS: usize = 64;

/// Addresses of recent successful SSH logins. From the journal where the system
/// keeps one, and from the text logs only where it does not: a user's
/// `logger -t sshd` lands in both, but journald records who really wrote it.
fn recent_ssh_logins() -> Vec<IpAddr> {
    logins(journal_sshd_messages(), || {
        ["/var/log/auth.log", "/var/log/secure"]
            .iter()
            .filter_map(|p| read_tail(p, 512 * 1024))
            .collect()
    })
}

/// The login addresses in sshd's journal messages (oldest first), or, with no
/// journal, in the text logs `logs` reads.
fn logins(journal: Option<String>, logs: impl FnOnce() -> Vec<String>) -> Vec<IpAddr> {
    match journal {
        Some(j) => first_addrs(j.lines().rev(), evidence_parse::accepted_message),
        None => login_addrs(logs().iter().map(String::as_str)),
    }
}

/// The login addresses in text logs (each oldest line first).
fn login_addrs<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<IpAddr> {
    first_addrs(
        texts.into_iter().flat_map(|t| t.lines().rev()),
        evidence_parse::accepted_login,
    )
}

/// The distinct addresses of successful logins in `lines` (newest first), at
/// most `MAX_LOG_LOGINS`. Only what sshd itself wrote as a success counts
/// (`evidence_parse::accepted_login`): sshd copies a client's chosen user name
/// into its failure lines, and that name must not be able to whitelist anyone.
fn first_addrs<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    accepted: fn(&str) -> Option<(&str, &str, IpAddr)>,
) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for line in lines {
        if out.len() >= MAX_LOG_LOGINS {
            break;
        }
        if let Some((_, _, ip)) = accepted(line) {
            let ip = net::normalize(ip);
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Most of the journal read for logins (20 000 of sshd's messages, at most 500
/// bytes each, fit), and how long journalctl may take.
const JOURNAL_MAX_BYTES: u64 = 12 * 1024 * 1024;
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);

/// sshd's recent messages, oldest first, from the journal: only those a root
/// sshd process sent. journald fills `_UID` and `_COMM` in from the sender's
/// credentials, so a line any other account logs with an `sshd` tag is not
/// among them. `None` where there is no journal to ask, or it holds nothing for
/// the last day (the system logs elsewhere).
fn journal_sshd_messages() -> Option<String> {
    let bin = util::find_bin("journalctl")?;
    let query = |args: &[&str], root_sshd: bool| {
        let mut cmd = Command::new(&bin);
        cmd.args(["--quiet", "--no-pager", "--output=cat"])
            .args(args);
        if root_sshd {
            cmd.args(["_UID=0", "_COMM=sshd", "_COMM=sshd-session"]);
        }
        run_capped(&mut cmd, JOURNAL_MAX_BYTES, JOURNAL_TIMEOUT)
    };
    // The day's logins, picked out of any flood of failures by journald. A
    // journalctl without `--grep` (systemd before 237, or no PCRE2), or one that
    // found nothing (it then fails), is asked for sshd's latest messages instead.
    let out = query(&["--since=-24h", "--grep=^Accepted "], true)
        .or_else(|| query(&["--lines=20000"], true))?;
    // Nothing from sshd: a quiet day, or a journal this system does not log to.
    // Only the second lets the text logs be read.
    if out.is_empty() && query(&["--since=-24h", "--lines=1"], false)?.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// What `cmd` printed, at most `max` bytes (output past that is cut and the
/// program stopped). `None` if it could not start, failed, or took longer than
/// `timeout`.
fn run_capped(cmd: &mut Command, max: u64, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let out = child.stdout.take();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(out) = out {
            let _ = out.take(max).read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    let got = rx.recv_timeout(timeout).ok();
    let full = got.as_ref().is_some_and(|b| b.len() as u64 >= max);
    if got.is_none() || full {
        let _ = child.kill();
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    got.filter(|_| full || status.success())
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

    fn cidr(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn an_admins_64_is_protected_but_the_vps_own_64_is_not() {
        // The admin is in over SSH from ::5; a colleague's device (or the
        // admin's own browser with a privacy address) in the same /64 showed up
        // in the log first.
        let mut wl = Whitelist::default();
        wl.push_admin(ip("2402:800:6310:12a::5"));
        assert!(wl.protects(ip("2402:800:6310:12a:aaaa::1")));
        assert!(key_protected("2402:800:6310:12a::/64", &wl, &[]));
        assert!(!key_protected("2402:800:6310:12b::/64", &wl, &[]));
        // The admin's /64 is whitelisted on the firewall too.
        assert_eq!(wl.keys(&[]), ["2402:800:6310:12a::/64"]);
        // IPv4 stays one address.
        wl.push_admin(ip("::ffff:198.51.100.4"));
        assert!(key_protected("198.51.100.4", &wl, &[]));
        assert!(!key_protected("198.51.100.5", &wl, &[]));
        // The VPS's own IPv6 address (or the hub's) protects itself only: on
        // a cloud that carves one /64 into many servers, the rest of it is
        // other customers, who may be banned like anyone.
        let mut wl = Whitelist::default();
        wl.push_own(ip("2604:a880:400:d1::7a3:e001"));
        wl.push_own(ip("198.51.100.20"));
        assert!(!key_protected("2604:a880:400:d1::/64", &wl, &[]));
        assert!(key_protected("198.51.100.20", &wl, &[]));
        assert!(wl.protects(ip("2604:a880:400:d1::7a3:e001")));
        assert!(!wl.protects(ip("2604:a880:400:d1::7a3:e002")));
        assert_eq!(wl.own_addrs().len(), 2);
        // A configured range, however narrow, and ranges never banned.
        let wl = Whitelist::of(vec![cidr("2001:db8:7:8::9")]);
        assert!(key_protected("2001:db8:7:8::/64", &wl, &[]));
        let cf = [cidr("2606:4700::/32")];
        assert!(key_protected(
            "2606:4700:10::/64",
            &Whitelist::default(),
            &cf
        ));
        assert!(!key_protected("x", &wl, &cf));
    }

    #[test]
    fn loopback_and_link_local_are_never_widened_to_a_64() {
        let mut wl = Whitelist::default();
        for s in ["fe80::1c2:3ff:fe4:5", "::1"] {
            wl.push_admin(ip(s));
        }
        assert_eq!(wl.keys(&[]), ["::1", "fe80::1c2:3ff:fe4:5"]);
        assert!(!key_protected("2001:db8::/64", &wl, &[]));
    }

    #[test]
    fn the_firewall_whitelist_never_holds_one_element_inside_another() {
        // What every host has: loopback plus `lo`'s 127.0.0.1, ::1, Cloudflare
        // both trusted and protected, an office range with an admin inside
        // it, an admin /64 inside a configured /48, a trusted load balancer
        // range holding the VPS's own interface address.
        let mut wl = Whitelist::of(vec![
            cidr("127.0.0.0/8"),
            cidr("::1/128"),
            cidr("203.0.113.0/24"),
            cidr("2001:db8::/48"),
        ]);
        wl.push_own(ip("127.0.0.1"));
        wl.push_own(ip("10.0.0.5"));
        wl.push_own(ip("::1"));
        wl.push_admin(ip("203.0.113.9"));
        wl.push_admin(ip("2001:db8:0:5::9"));
        wl.push_admin(ip("2001:db8:0:5::a"));
        let mut extra = snsec_common::ranges::cloudflare().to_vec();
        extra.extend_from_slice(snsec_common::ranges::cloudflare());
        extra.push(cidr("10.0.0.0/16"));
        let keys = wl.keys(&extra);
        let parsed: Vec<Cidr> = keys.iter().map(|k| cidr(k)).collect();
        for (i, a) in parsed.iter().enumerate() {
            for b in &parsed[i + 1..] {
                assert!(!a.overlaps(b), "{a:?} and {b:?} in {keys:?}");
            }
        }
        for want in [
            "127.0.0.0/8",
            "10.0.0.0/16",
            "203.0.113.0/24",
            "2001:db8::/48",
            "::1",
        ] {
            assert!(keys.iter().any(|k| k == want), "{want} in {keys:?}");
        }
        assert!(!keys.iter().any(|k| k == "::/64"));
    }

    #[test]
    fn the_hub_is_refused_only_for_configured_ranges_and_the_vps_own_addresses() {
        let mut wl = Whitelist::of(vec![cidr("203.0.113.0/24")]);
        wl.push_own(ip("198.51.100.20"));
        wl.push_admin(ip("192.0.2.44"));
        wl.push_peer(ip("192.0.2.45"));
        assert!(wl.refuses_hub_ban(cidr("203.0.113.7")));
        assert!(wl.refuses_hub_ban(cidr("198.51.100.20")));
        // An SSH session, and a panel or FTP connection, do not stop the
        // operator's ban.
        assert!(!wl.refuses_hub_ban(cidr("192.0.2.44")));
        assert!(!wl.refuses_hub_ban(cidr("192.0.2.45")));
        // A panel or FTP peer is only a session peer: never protected, never
        // on the firewall's whitelist.
        assert!(wl.session_peer("192.0.2.45"));
        assert!(!wl.session_peer("192.0.2.46"));
        assert!(!key_protected("192.0.2.45", &wl, &[]));
        assert!(!wl.keys(&[]).iter().any(|k| k == "192.0.2.45"));
        let mut wl = Whitelist::default();
        wl.push_peer(ip("2001:db8:9:9::5"));
        assert!(wl.session_peer("2001:db8:9:9::/64"));
    }

    #[test]
    fn admin_sessions_are_remembered_for_half_an_hour_and_the_memory_is_bounded() {
        let now = 1_000_000;
        let mut known = HashMap::new();
        let got = remember_admins(&mut known, &[ip("203.0.113.7")], now);
        assert_eq!(got, [ip("203.0.113.7")]);
        // The panel tab is closed: still whitelisted a while later...
        let got = remember_admins(&mut known, &[], now + ADMIN_MEMORY_SECS);
        assert_eq!(got, [ip("203.0.113.7")]);
        // ...but not forever.
        assert!(remember_admins(&mut known, &[], now + ADMIN_MEMORY_SECS + 1).is_empty());
        // A flood of distinct peers keeps only the most recent.
        let mut known = HashMap::new();
        for i in 0..(MAX_REMEMBERED_ADMINS as i64 + 50) {
            let peer = ip(&format!("10.9.{}.{}", i / 250, i % 250));
            remember_admins(&mut known, &[peer], now + i);
        }
        assert_eq!(known.len(), MAX_REMEMBERED_ADMINS);
        assert!(known.contains_key(&format!("10.9.{}.{}", 305 / 250, 305 % 250)));
        assert!(!known.contains_key("10.9.0.0"));
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

    fn conn(lport: u16, remote: &str, state: u8, inode: u64) -> netstat::Conn {
        netstat::Conn {
            local: ip("10.0.0.5"),
            local_port: lport,
            remote: ip(remote),
            remote_port: 50000,
            state,
            inode,
        }
    }

    #[test]
    fn on_sshds_ports_only_a_session_that_logged_in_is_whitelisted() {
        for t in [
            "sshd: ops@pts/0",
            "sshd: ops@notty",
            "sshd: ops",
            "sshd-session: ops@pts/1,pts/2",
            "sshd: alice@corp.example@pts/0",
        ] {
            assert!(logged_in_title(t), "{t}");
        }
        // Before a login the name in the title is the one the client offered.
        for t in [
            "sshd: [accepted]",
            "sshd: unknown [priv]",
            "sshd: root [net]",
            "sshd: alice@corp.example [priv]",
            "sshd-session: ops [priv]",
            "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
            "/usr/sbin/sshd -D -R",
            "sshd-auth: ops [net]",
            "sshd-session",
            "sshd: ",
            "xsshd: ops@pts/0",
        ] {
            assert!(!logged_in_title(t), "{t}");
        }
        let s = Sessions {
            sshd_ports: [22, 2200].into(),
            logged_in: [11, 17].into(),
            other_ports: [2083].into(),
        };
        let est = netstat::ST_ESTABLISHED;
        let conns = [
            conn(22, "203.0.113.7", est, 11),
            // Connected, never logged in, kept open.
            conn(22, "198.51.100.9", est, 12),
            conn(2200, "198.51.100.10", est, 13),
            conn(2200, "::ffff:203.0.113.8", est, 17),
            // A panel session, and a visitor of the web site.
            conn(2083, "192.0.2.4", est, 14),
            conn(443, "192.0.2.5", est, 15),
            // Closing.
            conn(22, "192.0.2.6", 0x06, 11),
        ];
        assert_eq!(
            session_peers(&conns, &s),
            Live {
                ssh: vec![ip("203.0.113.7"), ip("203.0.113.8")],
                // A panel session: only a session peer.
                other: vec![ip("192.0.2.4")],
            }
        );
    }

    #[test]
    fn with_a_journal_the_text_logs_are_not_read() {
        // What any account's `logger -t sshd` puts in the text log.
        let forged =
            "Oct 12 02:00:00 h sshd[1]: Accepted password for root from 6.6.6.6 port 1 ssh2\n";
        // sshd's own messages in the journal, oldest first.
        let journal = "Accepted publickey for ops from 203.0.113.7 port 50021 ssh2\n\
                       Accepted password for dev from 2001:db8::7 port 1 ssh2\n\
                       Failed password for invalid user Accepted password for a from 9.9.9.2 port 1 ssh2 from 9.9.9.9 port 5 ssh2\n\
                       Invalid user Accepted from 9.9.9.1 port 5\n\
                       Accepted publickey for ops from 203.0.113.7 port 50022 ssh2: ED25519 SHA256:k\n";
        assert_eq!(
            logins(Some(journal.into()), || panic!("text logs read")),
            [ip("203.0.113.7"), ip("2001:db8::7")]
        );
        assert!(logins(Some(String::new()), || panic!("text logs read")).is_empty());
        // Without a journal there is only the text log, read strictly.
        assert_eq!(logins(None, || vec![forged.into()]), [ip("6.6.6.6")]);
    }

    #[test]
    fn a_program_is_read_up_to_a_limit_and_a_failing_or_hanging_one_is_not() {
        let sh = |script: &str| {
            let mut c = Command::new("sh");
            c.args(["-c", script]);
            c
        };
        let t = Duration::from_secs(10);
        assert_eq!(
            run_capped(&mut sh("printf 'a\\nb\\n'"), 1024, t).as_deref(),
            Some(&b"a\nb\n"[..])
        );
        assert_eq!(
            run_capped(&mut sh("true"), 1024, t).as_deref(),
            Some(&b""[..])
        );
        assert_eq!(run_capped(&mut sh("printf x; exit 3"), 1024, t), None);
        assert_eq!(
            run_capped(&mut Command::new("/nonexistent/x"), 1024, t),
            None
        );
        // Endless output is cut, and the program stopped.
        assert_eq!(
            run_capped(&mut sh("exec yes"), 1000, t).map(|b| b.len()),
            Some(1000)
        );
        // One that hangs is given up on.
        let start = Instant::now();
        assert_eq!(
            run_capped(&mut sh("exec sleep 30"), 1024, Duration::from_millis(300)),
            None
        );
        assert!(start.elapsed() < Duration::from_secs(5));
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

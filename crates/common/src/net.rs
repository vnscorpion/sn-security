//! IP address and CIDR helpers shared by the log parser, the agent's
//! whitelist/ban logic and the hub.

use std::net::{IpAddr, Ipv6Addr};

/// A parsed CIDR range (single address = /32 or /128).
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Parse `1.2.3.4`, `1.2.3.0/24`, `2001:db8::/32`, `::1`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        if let Some((ip, p)) = s.split_once('/') {
            let addr: IpAddr = ip.trim().parse().ok()?;
            let prefix: u8 = p.trim().parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return None;
            }
            Some(Cidr { addr, prefix }.canonical())
        } else {
            let addr: IpAddr = s.parse().ok()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Some(Cidr { addr, prefix }.canonical())
        }
    }

    /// Does this range contain `ip`? IPv4 and IPv6 are compared within their
    /// own family; an IPv4-mapped IPv6 address is normalized to IPv4 first (and
    /// an IPv4-mapped range of at least /96 is the IPv4 range it maps).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let c = self.canonical();
        match (c.addr, normalize(ip)) {
            (IpAddr::V4(b), IpAddr::V4(x)) => prefix_eq(&b.octets(), &x.octets(), c.prefix),
            (IpAddr::V6(b), IpAddr::V6(x)) => prefix_eq(&b.octets(), &x.octets(), c.prefix),
            _ => false,
        }
    }

    /// The same range written plainly: an IPv4-mapped range of at least /96 as
    /// IPv4, the prefix within the family's length, the host bits cleared.
    #[must_use]
    pub fn canonical(&self) -> Cidr {
        let (addr, prefix) = match self.addr {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) if self.prefix >= 96 => (IpAddr::V4(v4), self.prefix - 96),
                _ => (IpAddr::V6(v6), self.prefix.min(128)),
            },
            v4 => (v4, self.prefix.min(32)),
        };
        let addr = match addr {
            IpAddr::V4(v4) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V4((u32::from(v4) & mask).into())
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6((u128::from(v6) & mask).into())
            }
        };
        Cidr { addr, prefix }
    }

    /// Do the two ranges share any address? Two prefixes either nest or are
    /// apart, so one of them holds the other's base address exactly when they
    /// overlap.
    #[must_use]
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }
}

/// The same addresses as `cidrs`, written without overlap: each range in its
/// canonical form, once, and none that another one already holds. An nftables
/// interval set without `auto-merge` refuses an element that overlaps another
/// (and with it the whole transaction), so a set is written from this. Two
/// prefixes either nest or are apart, so dropping the held ones leaves ranges
/// that are pairwise apart. Widest first, IPv4 before IPv6.
#[must_use]
pub fn minimal_cover(cidrs: &[Cidr]) -> Vec<Cidr> {
    let mut all: Vec<Cidr> = cidrs.iter().map(Cidr::canonical).collect();
    all.sort_by_key(|c| (c.addr.is_ipv6(), c.prefix, c.addr));
    let mut out: Vec<Cidr> = Vec::with_capacity(all.len());
    for c in all {
        let held = out.iter().any(|k| {
            k.addr.is_ipv6() == c.addr.is_ipv6() && k.prefix <= c.prefix && k.contains(c.addr)
        });
        if !held {
            out.push(c);
        }
    }
    out
}

/// Normalize `::ffff:a.b.c.d` to the plain IPv4 address.
#[must_use]
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// True if `ip` is inside any of `ranges`.
#[must_use]
pub fn in_any(ranges: &[Cidr], ip: IpAddr) -> bool {
    ranges.iter().any(|c| c.contains(ip))
}

/// Aggregate an IPv6 address to its /64 (the smallest unit worth banning for
/// IPv6, since a single host owns the whole /64). IPv4 is returned unchanged.
#[must_use]
pub fn ban_key(ip: IpAddr) -> String {
    match normalize(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut net = [0u8; 16];
            net[..8].copy_from_slice(&o[..8]);
            let prefix = Ipv6Addr::from(net);
            format!("{prefix}/64")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_cidr() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.255".parse().unwrap()));
        assert!(!c.contains("192.168.2.0".parse().unwrap()));
    }

    #[test]
    fn v6_cidr_and_mapped() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8:dead:beef::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
        // ::ffff:10.0.0.1 normalizes to 10.0.0.1
        let c4 = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c4.contains("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn single_host() {
        let c = Cidr::parse("203.0.113.7").unwrap();
        assert!(c.contains("203.0.113.7".parse().unwrap()));
        assert!(!c.contains("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn mapped_and_oversized_ranges_neither_panic_nor_lie() {
        let c = |s| Cidr::parse(s).unwrap();
        // An IPv4-mapped single address or range is the IPv4 one.
        assert!(c("::ffff:198.51.100.4").contains("198.51.100.4".parse().unwrap()));
        assert!(c("::ffff:10.0.0.0/104").contains("10.9.9.9".parse().unwrap()));
        assert!(!c("::ffff:10.0.0.0/104").contains("11.0.0.1".parse().unwrap()));
        // Wider than the mapped block: an IPv6 range, never a panic.
        assert!(!c("::ffff:0.0.0.0/64").contains("10.0.0.1".parse().unwrap()));
        // A prefix past the family's length, built by hand.
        let odd = Cidr {
            addr: "10.0.0.1".parse().unwrap(),
            prefix: 64,
        };
        assert!(odd.contains("10.0.0.1".parse().unwrap()));
        assert!(!odd.contains("10.0.0.2".parse().unwrap()));
        // Host bits are cleared when written out.
        let k = c("10.1.2.3/8").canonical();
        assert_eq!((k.addr.to_string(), k.prefix), ("10.0.0.0".to_string(), 8));
        let k = c("2001:db8:1:2::5/64").canonical();
        assert_eq!(k.addr.to_string(), "2001:db8:1:2::");
        let k = c("::ffff:198.51.100.4").canonical();
        assert_eq!(
            (k.addr.to_string(), k.prefix),
            ("198.51.100.4".to_string(), 32)
        );
        assert_eq!(c("0.0.0.0/0").canonical().prefix, 0);
    }

    #[test]
    fn ranges_overlap_when_one_holds_the_other() {
        let c = |s| Cidr::parse(s).unwrap();
        // A /128 (an SSH session) inside a /64 ban key, either way round.
        assert!(c("2001:db8:1:2::/64").overlaps(&c("2001:db8:1:2::5")));
        assert!(c("2001:db8:1:2::5").overlaps(&c("2001:db8:1:2::/64")));
        // A wide range around it, host bits set or not.
        assert!(c("2001:db8::/32").overlaps(&c("2001:db8:1:2::/64")));
        assert!(c("10.200.0.5/8").overlaps(&c("10.1.2.0/24")));
        assert!(c("10.1.2.0/24").overlaps(&c("10.200.0.5/8")));
        // Neighbours, and the other family.
        assert!(!c("2001:db8:1:3::/64").overlaps(&c("2001:db8:1:2::5")));
        assert!(!c("10.1.2.0/24").overlaps(&c("10.1.3.0/24")));
        assert!(!c("10.0.0.0/8").overlaps(&c("2001:db8::/32")));
    }

    #[test]
    fn a_cover_has_no_range_inside_another() {
        let c = |s| Cidr::parse(s).unwrap();
        let input = [
            // Loopback, and an interface address inside it.
            c("127.0.0.0/8"),
            c("127.0.0.1"),
            // The same Cloudflare range twice (trusted and protected).
            c("104.16.0.0/13"),
            c("104.16.0.0/13"),
            // An office range with an admin session inside it.
            c("203.0.113.0/24"),
            c("203.0.113.9"),
            // ::1 and an admin /64; a /64 inside a configured /48.
            c("::1"),
            c("2001:db8:1:2::/64"),
            c("2001:db8::/32"),
            c("2402:800:6310:12a::5"),
            c("2402:800:6310:12a::/64"),
            // Apart from everything.
            c("198.51.100.4"),
        ];
        let out = minimal_cover(&input);
        let shown: Vec<String> = out
            .iter()
            .map(|c| format!("{}/{}", c.addr, c.prefix))
            .collect();
        assert_eq!(
            shown,
            [
                "127.0.0.0/8",
                "104.16.0.0/13",
                "203.0.113.0/24",
                "198.51.100.4/32",
                "2001:db8::/32",
                "2402:800:6310:12a::/64",
                "::1/128",
            ]
        );
        for (i, a) in out.iter().enumerate() {
            for b in &out[i + 1..] {
                assert!(!a.overlaps(b), "{a:?} {b:?}");
            }
        }
        // Every input address is still covered.
        for c in &input {
            assert!(in_any(&out, c.addr), "{c:?}");
        }
        assert!(minimal_cover(&[]).is_empty());
    }

    #[test]
    fn ban_key_v6_is_64() {
        let k = ban_key("2001:db8:1:2:3:4:5:6".parse().unwrap());
        assert_eq!(k, "2001:db8:1:2::/64");
        let k4 = ban_key("1.2.3.4".parse().unwrap());
        assert_eq!(k4, "1.2.3.4");
    }
}

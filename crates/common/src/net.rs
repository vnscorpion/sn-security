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
            Some(Cidr { addr, prefix })
        } else {
            let addr: IpAddr = s.parse().ok()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Some(Cidr { addr, prefix })
        }
    }

    /// Does this range contain `ip`? IPv4 and IPv6 are compared within their
    /// own family; an IPv4-mapped IPv6 address is normalized to IPv4 first.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        let base = normalize(self.addr);
        match (base, ip) {
            (IpAddr::V4(b), IpAddr::V4(x)) => prefix_eq(&b.octets(), &x.octets(), self.prefix),
            (IpAddr::V6(b), IpAddr::V6(x)) => prefix_eq(&b.octets(), &x.octets(), self.prefix),
            _ => false,
        }
    }
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
    fn ban_key_v6_is_64() {
        let k = ban_key("2001:db8:1:2:3:4:5:6".parse().unwrap());
        assert_eq!(k, "2001:db8:1:2::/64");
        let k4 = ban_key("1.2.3.4".parse().unwrap());
        assert_eq!(k4, "1.2.3.4");
    }
}

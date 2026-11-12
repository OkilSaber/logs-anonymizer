//! Adresses IP : lecture tolérante (`1.2.3.4`, `1_2_3_4`, `{1, 2, 3, 4}`), plages CIDR,
//! adresses publiques.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = p.unwrap_or(max);
        (prefix <= max).then_some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(n) & mask == u32::from(*a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(n) & mask == u128::from(*a) & mask
            }
            _ => false,
        }
    }
}

pub fn is_public_v4(a: &Ipv4Addr) -> bool {
    let o = a.octets();
    !(o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] >= 224)
}

pub fn is_public_v6(a: &Ipv6Addr) -> bool {
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xff00) == 0xff00)
}

/// Lit une adresse écrite `1.2.3.4`, `2001:db8::1`, `51_75_10_28`, `2001_41d0_9a_a10_b03_701_0_1`
/// ou `{203, 0, 113, 10}` (y compris `{{203, 0, 113, 10}, 51234}`).
pub fn parse_loose(value: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(value).ok()?.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if s.contains('_') && !s.contains(['.', ':', ' ']) {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() == 4 {
            if let Ok(ip) = parts.join(".").parse::<Ipv4Addr>() {
                return Some(IpAddr::V4(ip));
            }
        }
        if let Ok(ip) = parts.join(":").parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(ip));
        }
        return None;
    }
    if s.starts_with('{') {
        let nums: Vec<u32> = s
            .split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<u32>().unwrap_or(u32::MAX))
            .collect();
        if nums.len() >= 4 && nums[..4].iter().all(|n| *n <= 255) && (nums.len() <= 5) {
            return Some(IpAddr::V4(Ipv4Addr::new(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8)));
        }
        if nums.len() >= 8 && nums[..8].iter().all(|n| *n <= 0xffff) && nums.len() <= 9 {
            let mut seg = [0u16; 8];
            for (i, n) in nums[..8].iter().enumerate() {
                seg[i] = *n as u16;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(seg)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_forms() {
        let v4: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(parse_loose(b"203.0.113.10"), Some(v4));
        assert_eq!(parse_loose(b"203_0_113_10"), Some(v4));
        assert_eq!(parse_loose(b"{203, 0, 113, 10}"), Some(v4));
        assert_eq!(parse_loose(b"{{203, 0, 113, 10}, 51234}"), Some(v4));
        assert_eq!(parse_loose(b"2001_41d0_9a_a10_b03_701_0_1"), Some("2001:41d0:9a:a10:b03:701:0:1".parse().unwrap()));
        assert_eq!(parse_loose(b"hackney/1.17.4"), None);
        assert_eq!(parse_loose(b"{:ok, 1}"), None);
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("2001:41d0:9a::/48").unwrap();
        assert!(c.contains(&"2001:41d0:9a:a12:ba04:9500:0:2".parse().unwrap()));
        assert!(!c.contains(&"2001:41d0:9b::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(&"10.200.3.4".parse().unwrap()));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(&"11.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("300.0.0.0/8").is_none());
    }

    #[test]
    fn public() {
        assert!(is_public_v4(&"198.51.100.65".parse().unwrap()));
        assert!(is_public_v4(&"51.75.10.28".parse().unwrap()));
        assert!(!is_public_v4(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public_v4(&"172.20.0.1".parse().unwrap()));
        assert!(is_public_v6(&"2001:41d0:9a::1".parse().unwrap()));
        assert!(!is_public_v6(&"fe80::1".parse().unwrap()));
        assert!(!is_public_v6(&"::1".parse().unwrap()));
    }
}

//! Adresses IP publiques, IPv4 et IPv6 (avec port collé : `2001:41d0:9a:aa0::2:65004`).

use super::{push, DetectorId, Finding};
use crate::netaddr::{is_public_v4, is_public_v6};
use memchr::memchr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Lit `a.b.c.d` à la position `s`. Rend la fin et l'adresse.
fn parse_v4(h: &[u8], s: usize) -> Option<(usize, Ipv4Addr)> {
    let mut oct = [0u8; 4];
    let mut i = s;
    for (n, slot) in oct.iter_mut().enumerate() {
        let ds = i;
        let mut v = 0u32;
        while i < h.len() && h[i].is_ascii_digit() && i - ds < 3 {
            v = v * 10 + (h[i] - b'0') as u32;
            i += 1;
        }
        if i == ds || v > 255 || (i < h.len() && h[i].is_ascii_digit()) {
            return None;
        }
        *slot = v as u8;
        if n < 3 {
            if h.get(i) != Some(&b'.') {
                return None;
            }
            i += 1;
        }
    }
    // Pas une version à 5 composants ni un identifiant plus long.
    match h.get(i) {
        Some(b'.') if h.get(i + 1).is_some_and(u8::is_ascii_digit) => None,
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => None,
        _ => Some((i, Ipv4Addr::from(oct))),
    }
}

pub fn v4(h: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < h.len() {
        if !h[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let boundary = i == 0 || !(h[i - 1].is_ascii_alphanumeric() || matches!(h[i - 1], b'.' | b'_'));
        if boundary {
            if let Some((end, addr)) = parse_v4(h, i) {
                if is_public_v4(&addr) {
                    push(out, i, end, DetectorId::Ipv4Public);
                }
                i = end;
                continue;
            }
        }
        while i < h.len() && h[i].is_ascii_digit() {
            i += 1;
        }
    }
}

/// Essaie de lire une IPv6 dans `run` ; si le dernier groupe est un port collé, il est retiré.
/// Rend la longueur de l'adresse dans `run`.
fn parse_v6(run: &[u8]) -> Option<(usize, Ipv6Addr)> {
    let parse = |b: &[u8]| std::str::from_utf8(b).ok()?.parse::<Ipv6Addr>().ok();
    if let Some(a) = parse(run) {
        return Some((run.len(), a));
    }
    let cut = memchr::memrchr(b':', run)?;
    parse(&run[..cut]).map(|a| (cut, a))
}

pub fn v6(h: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < h.len() {
        let Some(off) = memchr(b':', &h[i..]) else { break };
        let c = i + off;
        let mut s = c;
        while s > i && h[s - 1].is_ascii_hexdigit() {
            s -= 1;
        }
        let mut e = c;
        while e < h.len() && (h[e].is_ascii_hexdigit() || h[e] == b':') {
            e += 1;
        }
        i = e.max(c + 1);
        if s > 0 && (h[s - 1].is_ascii_alphanumeric() || h[s - 1] == b'.') {
            continue;
        }
        // Un `:` final isolé appartient à la ponctuation qui suit, pas à l'adresse.
        let mut end = e;
        while end > s + 1 && h[end - 1] == b':' && h[end - 2] != b':' {
            end -= 1;
        }
        let run = &h[s..end];
        if run.iter().filter(|b| **b == b':').count() < 2 {
            continue;
        }
        let Some((len, addr)) = parse_v6(run) else { continue };
        let groups = run[..len].split(|b| *b == b':').filter(|g| !g.is_empty()).count();
        if groups >= 3 && is_public_v6(&addr) {
            push(out, s, s + len, DetectorId::Ipv6Public);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::found;
    use super::super::DetectorId::*;

    #[test]
    fn ipv4_public_only() {
        assert_eq!(found(Ipv4Public, "Server: 203.0.113.10:443 (http)"), vec!["203.0.113.10"]);
        assert_eq!(found(Ipv4Public, "host: \"203.0.113.10\", peer 198.51.100.65:40461 [09/Nov"), vec!["203.0.113.10", "198.51.100.65"]);
        assert_eq!(found(Ipv4Public, "hds[{51.75.11.123:80|}]"), vec!["51.75.11.123"]);
        assert!(found(Ipv4Public, "10.0.0.1 192.168.1.20 127.0.0.1 172.16.5.4").is_empty());
        // Versions, pids, références, nombres décimaux.
        assert!(found(Ipv4Public, "hackney/1.17.4 <0.1166.0> #Reference<0.1590975473.2172125185.81270> 19.89 1.2.3.4.5 v1.2.3.4").is_empty());
        assert!(found(Ipv4Public, "999.1.1.1 1.2.3 1.2.3.4x").is_empty());
    }

    #[test]
    fn ipv6_with_glued_port() {
        assert_eq!(found(Ipv6Public, "haproxy[1]: 2001:41d0:9a:a10:b00:6100:0:1:56473 [09/Nov/2026:07:27:23.960]"), vec!["2001:41d0:9a:a10:b00:6100:0:1"]);
        assert_eq!(found(Ipv6Public, "2001:41d0:9a:aa0::2:65004 [x]"), vec!["2001:41d0:9a:aa0::2"]);
        assert_eq!(found(Ipv6Public, "[services@2001:41d0:9a:a12:ba04:9500:0:2][Elixir.Riak]"), vec!["2001:41d0:9a:a12:ba04:9500:0:2"]);
        assert_eq!(found(Ipv6Public, "addr 2a01:4f8::1: refused"), vec!["2a01:4f8::1"]);
        // Heures, typespecs, fichier:ligne, adresses locales.
        assert!(found(Ipv6Public, "06:50:50.270 [info] a :: b lib/x.ex:211: Mod ::1 fe80::1 00:00:16").is_empty());
    }
}

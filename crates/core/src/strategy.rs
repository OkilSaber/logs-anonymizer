//! Stratégies de remplacement et normalisation des valeurs.

use crate::netaddr;
use crate::pseudonym::Pseudonymizer;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Normalize {
    None,
    Trim,
    Lower,
    Email,
    /// Minuscules, sans accents, espaces réduits : « DUPONT » et « Dupont » coïncident.
    Casefold,
    Digits,
    /// `1.2.3.4`, `1_2_3_4` et `{1, 2, 3, 4}` coïncident.
    Ip,
}

impl Normalize {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Normalize::None,
            "trim" => Normalize::Trim,
            "lower" => Normalize::Lower,
            "email" => Normalize::Email,
            "casefold" => Normalize::Casefold,
            "digits" => Normalize::Digits,
            "ip" => Normalize::Ip,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mask {
    Email,
    Ipv4,
    KeepPrefix(usize),
    KeepSuffix(usize),
}

impl Mask {
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(n) = s.strip_prefix("keep_prefix:") {
            return n.trim().parse().ok().map(Mask::KeepPrefix);
        }
        if let Some(n) = s.strip_prefix("keep_suffix:") {
            return n.trim().parse().ok().map(Mask::KeepSuffix);
        }
        match s {
            "email" => Some(Mask::Email),
            "ipv4" => Some(Mask::Ipv4),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Pseudonymize { token: String, normalize: Normalize },
    Redact { label: String, preserve_scheme: bool },
    Mask(Mask),
    Hash { token: String },
    DropField,
    DropEntry,
    Keep,
}

impl Action {
    pub fn normalize(&self) -> Normalize {
        match self {
            Action::Pseudonymize { normalize, .. } => *normalize,
            _ => Normalize::None,
        }
    }
}

pub fn normalize(n: Normalize, v: &[u8]) -> Vec<u8> {
    match n {
        Normalize::None => v.to_vec(),
        Normalize::Trim => v.trim_ascii().to_vec(),
        Normalize::Lower | Normalize::Email => String::from_utf8_lossy(v.trim_ascii()).to_lowercase().into_bytes(),
        Normalize::Casefold => {
            let s = String::from_utf8_lossy(v);
            let folded: String = s.nfd().filter(|c| !unicode_normalization::char::is_combining_mark(*c)).collect::<String>().to_lowercase();
            folded.split_whitespace().collect::<Vec<_>>().join(" ").into_bytes()
        }
        Normalize::Digits => {
            let plus = v.trim_ascii().first() == Some(&b'+');
            let mut d: Vec<u8> = v.iter().copied().filter(u8::is_ascii_digit).collect();
            // +33 6 12 34 56 78 et 06 12 34 56 78 désignent le même numéro.
            if plus && d.len() == 11 && d.starts_with(b"33") {
                d.splice(..2, [b'0']);
            }
            d
        }
        Normalize::Ip => match netaddr::parse_loose(v) {
            Some(ip) => ip.to_string().into_bytes(),
            None => String::from_utf8_lossy(v.trim_ascii()).to_lowercase().into_bytes(),
        },
    }
}

fn mask(m: Mask, v: &[u8], out: &mut Vec<u8>) {
    let s = String::from_utf8_lossy(v);
    match m {
        Mask::Email => match s.split_once('@') {
            Some((local, domain)) => {
                let first = |x: &str| x.chars().next().map(String::from).unwrap_or_default();
                let tld = domain.rsplit_once('.').map(|(_, t)| t).unwrap_or("");
                out.extend_from_slice(format!("{}***@{}***.{}", first(local), first(domain), tld).as_bytes());
            }
            None => out.extend_from_slice(b"***"),
        },
        Mask::Ipv4 => {
            let parts: Vec<&str> = s.trim().split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                out.extend_from_slice(format!("{}.{}.x.x", parts[0], parts[1]).as_bytes());
            } else {
                out.extend_from_slice(b"***");
            }
        }
        Mask::KeepPrefix(n) => {
            out.extend_from_slice(s.chars().take(n).collect::<String>().as_bytes());
            out.extend_from_slice(b"***");
        }
        Mask::KeepSuffix(n) => {
            let count = s.chars().count();
            out.extend_from_slice(b"***");
            out.extend_from_slice(s.chars().skip(count.saturating_sub(n)).collect::<String>().as_bytes());
        }
    }
}

/// Écrit le remplacement de `value` dans `out`. `DropField`, `DropEntry` et `Keep` sont
/// traités par le moteur et ne passent pas ici.
pub fn apply(action: &Action, value: &[u8], pseudo: &Pseudonymizer, out: &mut Vec<u8>) {
    match action {
        Action::Pseudonymize { token, normalize: n } => pseudo.token(token, &normalize(*n, value), value, out),
        Action::Redact { label, preserve_scheme } => {
            if *preserve_scheme {
                // `Basic dXNl…` → `Basic [CREDENTIALS]`
                if let Some(sp) = value.iter().position(|b| *b == b' ') {
                    if (1..=16).contains(&sp) && sp + 1 < value.len() && value[..sp].iter().all(u8::is_ascii_alphabetic) {
                        out.extend_from_slice(&value[..=sp]);
                    }
                }
            }
            out.push(b'[');
            out.extend_from_slice(label.as_bytes());
            out.push(b']');
        }
        Action::Mask(m) => mask(*m, value, out),
        Action::Hash { token } => {
            let digest = Sha256::digest(value);
            out.extend_from_slice(token.as_bytes());
            out.push(b'_');
            for b in &digest[..8] {
                out.extend_from_slice(format!("{b:02x}").as_bytes());
            }
        }
        Action::DropField | Action::DropEntry | Action::Keep => out.extend_from_slice(b"[REDACTED]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(k: Normalize, v: &str) -> String {
        String::from_utf8(normalize(k, v.as_bytes())).unwrap()
    }

    fn a(action: Action, v: &str) -> String {
        let mut out = Vec::new();
        apply(&action, v.as_bytes(), &Pseudonymizer::new([1; 32], false), &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn normalizers() {
        assert_eq!(n(Normalize::Email, " JEAN.DUPONT@EXAMPLE.COM"), "jean.dupont@example.com");
        assert_eq!(n(Normalize::Casefold, "  DUPONT   Élodie "), "dupont elodie");
        assert_eq!(n(Normalize::Casefold, "Dupont Elodie"), "dupont elodie");
        assert_eq!(n(Normalize::Digits, "+33 6 12 34 56 78"), "0612345678");
        assert_eq!(n(Normalize::Digits, "06.12.34.56.78"), "0612345678");
        assert_eq!(n(Normalize::Ip, "{203, 0, 113, 10}"), "203.0.113.10");
        assert_eq!(n(Normalize::Ip, "51_75_10_28"), "51.75.10.28");
        assert_eq!(n(Normalize::Ip, "2001:41D0:9a:0:0:0:0:1"), "2001:41d0:9a::1");
    }

    #[test]
    fn strategies() {
        assert_eq!(a(Action::Redact { label: "CREDENTIALS".into(), preserve_scheme: true }, "Basic dXNlcjpwYXNz"), "Basic [CREDENTIALS]");
        assert_eq!(a(Action::Redact { label: "CREDENTIALS".into(), preserve_scheme: true }, "dXNlcjpwYXNz"), "[CREDENTIALS]");
        assert_eq!(a(Action::Redact { label: "SESSION".into(), preserve_scheme: false }, "a b"), "[SESSION]");
        assert_eq!(a(Action::Mask(Mask::Email), "jean.dupont@example.com"), "j***@e***.com");
        assert_eq!(a(Action::Mask(Mask::Ipv4), "51.75.10.28"), "51.75.x.x");
        assert_eq!(a(Action::Mask(Mask::KeepPrefix(2)), "75000"), "75***");
        assert_eq!(a(Action::Mask(Mask::KeepSuffix(4)), "4111111111111111"), "***1111");
        let h = a(Action::Hash { token: "HASH".into() }, "x");
        assert!(h.starts_with("HASH_") && h.len() == 5 + 16);
        let p = a(Action::Pseudonymize { token: "NAME".into(), normalize: Normalize::Casefold }, "DUPONT");
        assert_eq!(p, a(Action::Pseudonymize { token: "NAME".into(), normalize: Normalize::Casefold }, "Dupont"));
    }
}

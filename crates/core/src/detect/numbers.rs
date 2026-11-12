//! Téléphones, IBAN, cartes bancaires.

use super::{is_word, push, DetectorId, Finding};

fn digits_run(h: &[u8], s: usize) -> usize {
    let mut i = s;
    while i < h.len() && h[i].is_ascii_digit() {
        i += 1;
    }
    i
}

fn end_ok(h: &[u8], e: usize) -> bool {
    e >= h.len() || !is_word(h[e])
}

/// Numéro national français : `0X` + 8 chiffres, collés ou par paires séparées.
fn fr_phone(h: &[u8], s: usize) -> Option<usize> {
    if !(h.get(s) == Some(&b'0') && h.get(s + 1).is_some_and(|c| (b'1'..=b'9').contains(c))) {
        return None;
    }
    let run = digits_run(h, s);
    if run - s == 10 {
        return end_ok(h, run).then_some(run);
    }
    if run - s != 2 {
        return None;
    }
    let mut i = run;
    for _ in 0..4 {
        if !matches!(h.get(i), Some(b' ' | b'.' | b'-')) || digits_run(h, i + 1) != i + 3 {
            return None;
        }
        i += 3;
    }
    end_ok(h, i).then_some(i)
}

/// Numéro international : `+` puis 8 à 15 chiffres, séparateurs simples admis.
fn intl_phone(h: &[u8], s: usize) -> Option<usize> {
    if !h.get(s + 1).is_some_and(|c| (b'1'..=b'9').contains(c)) {
        return None;
    }
    let mut i = s + 1;
    let mut n = 0;
    let mut end = i;
    while i < h.len() {
        if h[i].is_ascii_digit() {
            n += 1;
            i += 1;
            end = i;
        } else if matches!(h[i], b' ' | b'.' | b'-') && h.get(i + 1).is_some_and(u8::is_ascii_digit) {
            i += 1;
        } else {
            break;
        }
    }
    ((8..=15).contains(&n) && end_ok(h, end)).then_some(end)
}

pub fn phone(h: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < h.len() {
        let prev = if i == 0 { b' ' } else { h[i - 1] };
        let found = match h[i] {
            b'+' if !is_word(prev) => intl_phone(h, i),
            b'0' if !(is_word(prev) || matches!(prev, b'.' | b'+' | b'-' | b':' | b'/' | b',')) => fr_phone(h, i),
            _ => None,
        };
        match found {
            Some(end) => {
                push(out, i, end, DetectorId::Phone);
                i = end;
            }
            None => i += 1,
        }
    }
}

fn iban_valid(s: &[u8]) -> bool {
    let mut rem = 0u32;
    for &b in s[4..].iter().chain(&s[..4]) {
        let v = if b.is_ascii_digit() { (b - b'0') as u32 } else { (b - b'A') as u32 + 10 };
        rem = if v < 10 { (rem * 10 + v) % 97 } else { (rem * 100 + v) % 97 };
    }
    rem == 1
}

/// IBAN compact (sans espaces), validé par le modulo 97.
pub fn iban(h: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    while i + 15 <= h.len() {
        let boundary = i == 0 || !h[i - 1].is_ascii_alphanumeric();
        if boundary && h[i].is_ascii_uppercase() && h[i + 1].is_ascii_uppercase() && h[i + 2].is_ascii_digit() && h[i + 3].is_ascii_digit() {
            let mut e = i + 4;
            while e < h.len() && (h[e].is_ascii_uppercase() || h[e].is_ascii_digit()) {
                e += 1;
            }
            if (15..=34).contains(&(e - i)) && (e >= h.len() || !h[e].is_ascii_alphanumeric()) && iban_valid(&h[i..e]) {
                push(out, i, e, DetectorId::Iban);
            }
            i = e;
        } else {
            i += 1;
        }
    }
}

fn luhn(d: &[u8]) -> bool {
    let mut sum = 0u32;
    for (k, &c) in d.iter().rev().enumerate() {
        let mut v = c as u32;
        if k % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

/// Préfixe et longueur d'un réseau de cartes connu : écarte les identifiants numériques
/// quelconques, qui passent Luhn une fois sur dix.
fn known_network(d: &[u8]) -> bool {
    let n = d.len();
    let p2 = d[0] as u32 * 10 + d[1] as u32;
    let p4 = p2 * 100 + d[2] as u32 * 10 + d[3] as u32;
    (d[0] == 4 && matches!(n, 13 | 16 | 19))
        || ((51..=55).contains(&p2) && n == 16)
        || ((2221..=2720).contains(&p4) && n == 16)
        || (matches!(p2, 34 | 37) && n == 15)
        || ((p4 == 6011 || p2 == 65 || p2 == 62 || p2 == 35) && (16..=19).contains(&n))
        || (matches!(p2, 30 | 36 | 38) && n == 14)
}

/// 13 à 19 chiffres collés, ou 4 groupes de 4 séparés par un espace ou un tiret.
pub fn card(h: &[u8], out: &mut Vec<Finding>) {
    let mut i = 0;
    let mut digits = Vec::with_capacity(19);
    while i < h.len() {
        if !h[i].is_ascii_digit() || (i > 0 && (is_word(h[i - 1]) || matches!(h[i - 1], b'.' | b'-'))) {
            i += 1;
            continue;
        }
        let run = digits_run(h, i);
        digits.clear();
        let mut end = run;
        if run - i == 4 {
            let mut j = i;
            for g in 0..4 {
                if g > 0 {
                    if !matches!(h.get(j), Some(b' ' | b'-')) {
                        break;
                    }
                    j += 1;
                }
                if digits_run(h, j) != j + 4 {
                    break;
                }
                digits.extend(h[j..j + 4].iter().map(|c| c - b'0'));
                j += 4;
            }
            end = j;
        } else {
            digits.extend(h[i..run].iter().map(|c| c - b'0'));
        }
        let n = digits.len();
        let grouped_ok = run - i != 4 || n == 16;
        if grouped_ok && (13..=19).contains(&n) && end_ok(h, end) && h.get(end) != Some(&b'.') && known_network(&digits) && luhn(&digits) {
            push(out, i, end, DetectorId::CardLuhn);
            i = end;
        } else {
            i = run;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::found;
    use super::super::DetectorId::*;

    #[test]
    fn phones() {
        assert_eq!(found(Phone, "\"mobilephone\": \"0600000000\""), vec!["0600000000"]);
        assert_eq!(found(Phone, "tel 06 12 34 56 78, ou +33 6 12 34 56 78."), vec!["06 12 34 56 78", "+33 6 12 34 56 78"]);
        assert_eq!(found(Phone, "+33612345678"), vec!["+33612345678"]);
        // Numéros de commande, horodatages, durées, tailles.
        assert!(found(Phone, "\"orderid\": \"900449662\" 1794217138 0.11353 sz[2159] 2026101315150683 id_0612345678 1.0600000000").is_empty());
        assert!(found(Phone, "sort=_yz_rk+desc q=[*+TO+NOW-1DAY] 00:00:16.060").is_empty());
    }

    #[test]
    fn ibans() {
        assert_eq!(found(Iban, "iban: FR7630006000011234567890189,"), vec!["FR7630006000011234567890189"]);
        assert!(found(Iban, "FR7630006000011234567890188 ETAM_0063 AB12").is_empty());
    }

    #[test]
    fn cards() {
        assert_eq!(found(CardLuhn, "pan=4111111111111111;"), vec!["4111111111111111"]);
        assert_eq!(found(CardLuhn, "card 5555 5555 5555 4444 ok"), vec!["5555 5555 5555 4444"]);
        // Luhn faux, réseau inconnu, identifiants et horodatages.
        assert!(found(CardLuhn, "4111111111111112 1794217138000 2026101315150683 655485594002 900449662").is_empty());
    }
}

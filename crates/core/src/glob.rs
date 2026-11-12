//! Globs minimalistes : `*` (zéro ou plusieurs octets) et `?` (un octet).

/// Correspondance sensible à la casse ; l'appelant met en minuscules si besoin.
pub fn glob_match(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Insensible à la casse ASCII.
pub fn glob_match_ci(p: &str, t: &str) -> bool {
    glob_match(p.to_ascii_lowercase().as_bytes(), t.to_ascii_lowercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert!(glob_match(b"addressline*", b"addressline1"));
        assert!(glob_match(b"address?", b"address1"));
        assert!(!glob_match(b"address?", b"address"));
        assert!(glob_match(b"customer*name", b"customerfirstname"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"*phone*", b"mobilephone"));
        assert!(!glob_match(b"city", b"cityname"));
        assert!(glob_match_ci("etam_*_gateway", "ETAM_sb_gateway"));
    }
}

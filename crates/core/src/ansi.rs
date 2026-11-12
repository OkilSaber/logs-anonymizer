//! Retrait des séquences d'échappement ANSI.

use memchr::memchr;

pub fn has_esc(input: &[u8]) -> bool {
    memchr(0x1b, input).is_some()
}

/// Copie `input` dans `out` sans les séquences `ESC [ … <final>` ni les `ESC <octet>`.
pub fn strip_ansi(input: &[u8], out: &mut Vec<u8>) {
    let len = input.len();
    let mut i = 0;
    while let Some(p) = memchr(0x1b, &input[i..]) {
        out.extend_from_slice(&input[i..i + p]);
        let mut j = i + p + 1;
        if j < len && input[j] == b'[' {
            j += 1;
            while j < len && !(0x40..=0x7e).contains(&input[j]) {
                j += 1;
            }
            if j < len {
                j += 1;
            }
        } else if j < len {
            j += 1;
        }
        i = j;
    }
    out.extend_from_slice(&input[i..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(s: &[u8]) -> Vec<u8> {
        let mut o = Vec::new();
        strip_ansi(s, &mut o);
        o
    }

    #[test]
    fn strips_colors() {
        assert_eq!(strip(b"\x1b[0m\x1b[36m"), b"");
        assert_eq!(strip(b"\x1b[0mERROR {"), b"ERROR {");
        assert_eq!(strip(b"http_code: \x1b[33m404\x1b[39m"), b"http_code: 404");
        assert_eq!(strip(b"plain"), b"plain");
        assert_eq!(strip(b"cut \x1b["), b"cut ");
    }
}

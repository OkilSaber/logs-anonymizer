//! Métadonnées Plug : lignes de continuation préfixées par une tabulation.
//!
//! `\t<nom> : <valeur brute>` (cookie, authorization) et `\t<nom>: <terme>` (qs).

use super::{cookie, elixir_term, ExtractorId, ExtractorSet, Spans, ValueKind};
use memchr::memchr;

pub fn scan(text: &[u8], header_len: usize, set: &ExtractorSet, sp: &mut Spans) {
    let len = text.len();
    let mut nl = header_len;
    while nl < len {
        let ls = nl + 1;
        let le = memchr(b'\n', &text[ls.min(len)..]).map(|o| ls + o).unwrap_or(len);
        let mut next = le;
        if text.get(ls) == Some(&b'\t') {
            let consumed = line(text, ls + 1, le, set, sp);
            if consumed > le {
                // Un terme multiligne a été consommé : reprendre à la fin de sa dernière ligne.
                next = memchr(b'\n', &text[consumed..]).map(|o| consumed + o).unwrap_or(len);
            }
        }
        nl = next;
    }
}

/// Traite une ligne de métadonnée ; rend la position de fin de ce qui a été consommé.
fn line(text: &[u8], s: usize, le: usize, set: &ExtractorSet, sp: &mut Spans) -> usize {
    let mut i = s;
    while i < le && (text[i].is_ascii_alphanumeric() || matches!(text[i], b'_' | b'-')) {
        i += 1;
    }
    if i == s {
        return le;
    }
    let name = &text[s..i];
    let rest = &text[i..le];
    let (vs, term_style) = if rest.starts_with(b" : ") {
        (i + 3, false)
    } else if rest.starts_with(b": ") {
        (i + 2, true)
    } else {
        return le;
    };
    let mut ve = le;
    while ve > vs && text[ve - 1] == b' ' {
        ve -= 1;
    }
    if vs >= ve {
        return le;
    }

    let m0 = sp.push_seg(b"meta");
    let m1 = sp.push_seg(name);
    let mut end = le;
    let lower = name.to_ascii_lowercase();
    if set.elixir_term && term_style && matches!(text[vs], b'%' | b'[' | b'{' | b'"') {
        end = elixir_term::parse_at(text, vs, sp, set.max_depth).max(le);
    } else if set.cookie && (lower == b"cookie" || lower == b"set-cookie") {
        if cookie::parse(text, vs, ve, lower == b"set-cookie", sp) == 0 {
            sp.leaf(vs, ve, ExtractorId::PlugMetadata, ValueKind::Raw, false);
        }
    } else {
        sp.leaf(vs, ve, ExtractorId::PlugMetadata, ValueKind::Raw, false);
    }
    sp.pop_seg(m1);
    sp.pop_seg(m0);
    sp.claim(s, end);
    end
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};

    fn extract(text: &[u8]) -> Vec<(String, String)> {
        let mut sp = Spans::default();
        let header = memchr::memchr(b'\n', text).unwrap_or(text.len());
        run(text, header, None, &ExtractorSet::default(), &mut sp);
        dump(text, &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn cookie_authorization_and_qs() {
        let text = b"09:39:05.203 [info]  in GET /api/x\n\tqs: %{\"brand\" => \"etam\", \"from\" => \"2026-10-31\"}\n\tcookie : etam_admin-auth=jean.dupont@example.com%7C1794217138%7CAbCd=; other=1\n\tauthorization : Basic dXNlcjpwYXNzd29yZA==\n\t#Reference<0.1.2.3>";
        assert_eq!(
            extract(text),
            vec![
                s("meta.qs.brand", "etam"),
                s("meta.qs.from", "2026-10-31"),
                s("meta.cookie.etam_admin-auth", "jean.dupont@example.com%7C1794217138%7CAbCd="),
                s("meta.cookie.other", "1"),
                s("meta.authorization", "Basic dXNlcjpwYXNzd29yZA=="),
            ]
        );
    }

    #[test]
    fn unparsable_cookie_is_kept_whole() {
        let text = b"h\n\tcookie : garbage-without-equals";
        assert_eq!(extract(text), vec![s("meta.cookie", "garbage-without-equals")]);
    }
}

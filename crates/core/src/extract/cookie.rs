//! `nom=valeur; nom2=valeur2` → une valeur par cookie, au chemin `<parent>.<nom>`.

use super::{ExtractorId, Spans, ValueKind};

/// Rend le nombre de cookies trouvés. `first_only` pour `set-cookie` (les attributs
/// `Path=`, `Expires=`… ne sont pas des cookies).
pub fn parse(text: &[u8], start: usize, end: usize, first_only: bool, sp: &mut Spans) -> usize {
    let mut found = 0;
    let mut i = start;
    while i < end {
        let part_end = memchr::memchr(b';', &text[i..end]).map(|o| i + o).unwrap_or(end);
        let mut s = i;
        while s < part_end && text[s] == b' ' {
            s += 1;
        }
        if let Some(eq) = memchr::memchr(b'=', &text[s..part_end]) {
            let name = text[s..s + eq].trim_ascii();
            let vs = s + eq + 1;
            let mut ve = part_end;
            while ve > vs && text[ve - 1] == b' ' {
                ve -= 1;
            }
            if !name.is_empty() && name.iter().all(|b| b.is_ascii_graphic()) {
                let mark = sp.push_seg(name);
                sp.leaf(vs, ve, ExtractorId::Cookie, ValueKind::Raw, false);
                sp.pop_seg(mark);
                found += 1;
                if first_only {
                    break;
                }
            }
        }
        i = part_end + 1;
    }
    found
}

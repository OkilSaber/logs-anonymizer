//! Lexer JSON tolérant : multiligne, tronqué, embarqué dans du texte.

use super::{ExtractorId, Pair, Spans, ValueKind};
use memchr::memchr2;

pub fn scan(text: &[u8], sp: &mut Spans, max_depth: usize) {
    let mut i = 0;
    while i < text.len() {
        let Some(off) = memchr2(b'{', b'[', &text[i..]) else { break };
        let p = i + off;
        let glued = p > 0 && (text[p - 1] == b'%' || text[p - 1].is_ascii_alphanumeric());
        if glued || sp.is_claimed(p) || !plausible(text, p) {
            i = p + 1;
            continue;
        }
        let mut parser = Parser { t: text, i: p, sp, max_depth };
        parser.value(0);
        let end = parser.i.max(p + 1);
        sp.claim(p, end);
        i = end;
    }
}

fn skip_ws(t: &[u8], mut i: usize) -> usize {
    while i < t.len() && t[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// `{` suivi de `"clé" :`, ou `[` suivi d'un tel objet.
fn plausible(t: &[u8], p: usize) -> bool {
    let mut i = skip_ws(t, p + 1);
    if t[p] == b'[' {
        if t.get(i) != Some(&b'{') {
            return false;
        }
        i = skip_ws(t, i + 1);
    }
    if t.get(i) != Some(&b'"') {
        return false;
    }
    i += 1;
    while i < t.len() {
        match t[i] {
            b'\\' => i += 2,
            b'"' => return t.get(skip_ws(t, i + 1)) == Some(&b':'),
            b'\n' => return false,
            _ => i += 1,
        }
    }
    false
}

struct Parser<'a> {
    t: &'a [u8],
    i: usize,
    sp: &'a mut Spans,
    max_depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        self.i = skip_ws(self.t, self.i);
    }

    /// À l'appel, `self.i` est sur le guillemet ouvrant. Rend (début, fin, fermée).
    fn string(&mut self) -> (usize, usize, bool) {
        let s = self.i + 1;
        let mut j = s;
        while j < self.t.len() {
            match self.t[j] {
                b'\\' => j += 2,
                b'"' => {
                    self.i = j + 1;
                    return (s, j, true);
                }
                b'\n' => break,
                _ => j += 1,
            }
        }
        let e = j.min(self.t.len());
        self.i = e;
        (s, e, false)
    }

    /// Rend `false` si la valeur est tronquée ou invalide ; les spans déjà émis sont gardés.
    fn value(&mut self, depth: usize) -> bool {
        self.ws();
        let Some(&c) = self.t.get(self.i) else { return false };
        if depth > self.max_depth {
            return false;
        }
        match c {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => {
                let (s, e, closed) = self.string();
                self.sp.leaf(s, e, ExtractorId::Json, ValueKind::Str, false);
                closed
            }
            b'-' | b'0'..=b'9' => {
                let s = self.i;
                while self.i < self.t.len() && matches!(self.t[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                    self.i += 1;
                }
                self.sp.leaf(s, self.i, ExtractorId::Json, ValueKind::Number, true);
                true
            }
            _ => {
                for lit in [&b"true"[..], b"false", b"null"] {
                    if self.t[self.i..].starts_with(lit) {
                        self.i += lit.len();
                        return true;
                    }
                }
                false
            }
        }
    }

    fn object(&mut self, depth: usize) -> bool {
        self.i += 1;
        let mut pair = Pair::default();
        let base = self.sp.cur_len();
        loop {
            self.ws();
            match self.t.get(self.i) {
                Some(b'}') => {
                    self.i += 1;
                    return true;
                }
                Some(b'"') => {}
                _ => return false,
            }
            let key_start = self.i;
            let (ks, ke, closed) = self.string();
            if !closed {
                return false;
            }
            self.ws();
            if self.t.get(self.i) != Some(&b':') {
                return false;
            }
            self.i += 1;
            let t = self.t;
            let mark = self.sp.push_seg(&t[ks..ke]);
            let idx = self.sp.items.len();
            let ok = self.value(depth + 1);
            if self.sp.items.len() == idx + 1 {
                self.sp.items[idx].field = Some((key_start as u32, self.i as u32));
            }
            self.sp.pop_seg(mark);
            pair.note(&t[ks..ke], idx, t, base, self.sp);
            if !ok {
                return false;
            }
            self.ws();
            match self.t.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }

    fn array(&mut self, depth: usize) -> bool {
        self.i += 1;
        loop {
            self.ws();
            if self.t.get(self.i) == Some(&b']') {
                self.i += 1;
                return true;
            }
            if !self.value(depth + 1) {
                return false;
            }
            self.ws();
            match self.t.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return true;
                }
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};

    fn extract(text: &[u8]) -> Vec<(String, String)> {
        let mut sp = Spans::default();
        run(text, memchr::memchr(b'\n', text).unwrap_or(text.len()), None, &ExtractorSet::default(), &mut sp);
        dump(text, &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn multiline_truncated_then_one_line() {
        let text = br#"04:58:03.747 [info]  /api/order
(payload):
{
 "orderid": "900449662",
 "ordertotal": 19.89,
 "billingaddress": {
   "customername": "Dupont",
   "city": "Paris"
 },
...
(response):
200 -> {"delivery_modes":[],"ok":true,"n":{"deep":"v"}}"#;
        assert_eq!(
            extract(text),
            vec![
                s("orderid", "900449662"),
                s("ordertotal", "19.89"),
                s("billingaddress.customername", "Dupont"),
                s("billingaddress.city", "Paris"),
                s("n.deep", "v"),
            ]
        );
    }

    #[test]
    fn escapes_and_delimiters_inside_strings() {
        let text = br#"x {"a": "va,l}u\"e", "b": ["x]y", {"c": "d"}], "e": "f"}"#;
        assert_eq!(
            extract(text),
            vec![s("a", r#"va,l}u\"e"#), s("b", "x]y"), s("b.c", "d"), s("e", "f")]
        );
    }

    #[test]
    fn array_indices_are_omitted_and_truncated_string_is_kept() {
        let text = br#"{"products":[{"id":"655485594002","quantity":1}],"shipping_address":{"address1":"1 rue de l'Exem"#;
        assert_eq!(
            extract(text),
            vec![
                s("products.id", "655485594002"),
                s("products.quantity", "1"),
                s("shipping_address.address1", "1 rue de l'Exem"),
            ]
        );
    }

    #[test]
    fn name_value_pairs_take_the_name_as_key() {
        let text = br#"x {"properties":[{"name":"firstName","value":"Jean"},{"value":{"city":"Paris"},"name":"address"},{"name":"n","value":"tronq"#;
        assert_eq!(
            extract(text),
            vec![
                s("properties.name", "firstName"),
                s("properties.firstname", "Jean"),
                s("properties.address.city", "Paris"),
                s("properties.name", "address"),
                s("properties.name", "n"),
                s("properties.n", "tronq"),
            ]
        );
    }

    #[test]
    fn not_json() {
        assert!(extract(b"10:00:00.000 [info]  tuple {\"a\", 1} sz[174] [info] {}").is_empty());
    }
}

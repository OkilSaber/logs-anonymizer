//! Paramètres de la query string d'une requête, aux chemins `url.query.<paramètre>`.
//!
//! La clé est URL-décodée (puis mise en minuscules comme tout segment de chemin) ; la
//! valeur est laissée telle quelle dans le texte, encodage compris.

use super::{ExtractorId, Spans, ValueKind};
use crate::http::Request;
use memchr::memchr;

/// Au-delà, ce n'est pas un nom de paramètre.
const MAX_KEY: usize = 128;

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `%XX` → octet, `+` → espace ; un `%` mal formé est gardé tel quel.
pub(crate) fn url_decode(raw: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < raw.len() {
        let decoded = match raw[i] {
            b'%' => raw.get(i + 1).copied().and_then(hex).zip(raw.get(i + 2).copied().and_then(hex)).map(|(hi, lo)| hi << 4 | lo),
            _ => None,
        };
        match decoded {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(if raw[i] == b'+' { b' ' } else { raw[i] });
                i += 1;
            }
        }
    }
}

pub fn scan(text: &[u8], req: &Request, sp: &mut Spans) {
    let Some((qs, qe)) = req.query else { return };
    let (qs, qe) = (qs.min(text.len()), qe.min(text.len()));
    let url = sp.push_seg(b"url");
    let query = sp.push_seg(b"query");
    let mut key = Vec::new();
    let mut i = qs;
    while i < qe {
        let end = memchr(b'&', &text[i..qe]).map_or(qe, |o| i + o);
        if let Some(eq) = memchr(b'=', &text[i..end]).map(|o| i + o) {
            if eq > i && eq - i <= MAX_KEY {
                key.clear();
                url_decode(&text[i..eq], &mut key);
                let mark = sp.push_seg(&key);
                sp.leaf(eq + 1, end, ExtractorId::HttpRequest, ValueKind::Raw, false);
                sp.pop_seg(mark);
            }
        }
        i = end + 1;
    }
    sp.pop_seg(query);
    sp.pop_seg(url);
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};
    use super::url_decode;
    use crate::format::{make_format, FormatKind};

    fn extract(kind: FormatKind, header: &str) -> Vec<(String, String)> {
        let format = make_format(kind).unwrap();
        let mut sp = Spans::default();
        let set = ExtractorSet { http_request: true, plug_metadata: false, cookie: false, json: false, elixir_term: false, ..ExtractorSet::default() };
        let req = format.request(header.as_bytes());
        run(header.as_bytes(), header.len(), req.as_ref(), &set, &mut sp);
        dump(header.as_bytes(), &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn decodes_keys() {
        let d = |raw: &str| {
            let mut out = Vec::new();
            url_decode(raw.as_bytes(), &mut out);
            String::from_utf8_lossy(&out).into_owned()
        };
        assert_eq!(d("SAMLResponse"), "SAMLResponse");
        assert_eq!(d("user%5Bname%5D"), "user[name]");
        assert_eq!(d("a+b%20c"), "a b c");
        assert_eq!(d("100%"), "100%");
        assert_eq!(d("%4"), "%4");
        assert_eq!(d("%zz%41"), "%zzA");
    }

    #[test]
    fn elixir_header_forms() {
        let x = |h: &str| extract(FormatKind::ElixirSyslog, h);
        assert_eq!(x("09:39:05.203 [info]  in GET /api/x?brand=etam&from=2026-10-31"), vec![s("url.query.brand", "etam"), s("url.query.from", "2026-10-31")]);
        assert_eq!(x("09:39:05.229 [info]  Sent 200 in 26ms\tGET /login?user=bob&password=hunter22&next=/"), vec![
            s("url.query.user", "bob"),
            s("url.query.password", "hunter22"),
            s("url.query.next", "/"),
        ]);
        assert_eq!(x("06:49:31.793 [info] GET //api/user/M0000001?Access_Token=abc%3D%3D done"), vec![s("url.query.access_token", "abc%3D%3D")]);
        // Clé encodée, valeur vide, paramètre sans `=`, `=` dans la valeur, point dans la clé.
        assert_eq!(x("06:49:31.793 [info] GET /x?user%5Bname%5D=bob&empty=&flag&eq=a=b&a.b=1&&=x"), vec![
            s("url.query.user[name]", "bob"),
            s("url.query.eq", "a=b"),
            s("url.query.a_b", "1"),
        ]);
        assert_eq!(x("09:39:05.203 [info]  in GET /api/x"), vec![]);
        assert_eq!(x("09:39:05.203 [info]  in GET /api/x?"), vec![]);
        assert_eq!(x("09:39:05.203 [info]  no request here ?a=b"), vec![]);
    }

    #[test]
    fn haproxy_request_field() {
        let line = |req: &str| {
            format!("198.51.100.74:43078 [09/Nov/2026:00:10:02.290] f b/s tls[-/-/0] t[0/0/0/4/4] c[302] sz[310] - - ---- 1/1/0/0/0 0/0 hds[{{}}] req[\"{req}\"]")
        };
        let x = |req: &str| extract(FormatKind::HaproxySyslog, &line(req));
        assert_eq!(
            x("GET /auth/callback?SAMLResponse=PHNhbWxwOlJlc3BvbnNl%3D%3D&state=abc HTTP/1.1"),
            vec![s("url.query.samlresponse", "PHNhbWxwOlJlc3BvbnNl%3D%3D"), s("url.query.state", "abc")]
        );
        assert_eq!(
            x("GET /search/query/idx?q=last_notification:[*+TO+NOW-1DAY]&wt=json&rows=1000000 HTTP/1.1"),
            vec![s("url.query.q", "last_notification:[*+TO+NOW-1DAY]"), s("url.query.wt", "json"), s("url.query.rows", "1000000")]
        );
        // Requête coupée par syslog : le dernier paramètre va jusqu'au bout de la ligne.
        let cut = line("GET /login?password=hunter22");
        let cut = &cut[..cut.len() - 2];
        assert_eq!(extract(FormatKind::HaproxySyslog, cut), vec![s("url.query.password", "hunter22")]);
        assert_eq!(x("<BADREQ>"), vec![]);
        assert_eq!(x("GET / HTTP/1.1"), vec![]);
    }
}

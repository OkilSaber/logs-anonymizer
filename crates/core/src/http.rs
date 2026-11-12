//! Requête HTTP dans une ligne d'en-tête (`in GET /x`, `Sent 200 in 26ms\tGET /x`,
//! `GET //api/x`, `/api/order`) et motifs de route (`[MÉTHODE ]/seg/{nom}/*/**`).

use crate::glob::glob_match;

const METHODS: [&[u8]; 8] = [b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS", b"TRACE"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: Option<(usize, usize)>,
    /// Chemin, sans la query string.
    pub path: (usize, usize),
    pub query: Option<(usize, usize)>,
}

/// Cherche `MÉTHODE /chemin` dans la ligne, ou un chemin seul en premier mot.
pub fn find_request(line: &[u8], from: usize) -> Option<Request> {
    let mut i = from;
    let mut prev_method: Option<(usize, usize)> = None;
    let mut first = true;
    while i < line.len() {
        while i < line.len() && matches!(line[i], b' ' | b'\t') {
            i += 1;
        }
        let s = i;
        while i < line.len() && !matches!(line[i], b' ' | b'\t') {
            i += 1;
        }
        if s == i {
            break;
        }
        let word = &line[s..i];
        if word[0] == b'/' && (prev_method.is_some() || first) {
            let (path_end, query) = match memchr::memchr(b'?', word) {
                Some(q) => (s + q, Some((s + q + 1, i))),
                None => (i, None),
            };
            return Some(Request { method: prev_method, path: (s, path_end), query });
        }
        prev_method = METHODS.contains(&word).then_some((s, i));
        first = false;
    }
    None
}

#[derive(Clone, Debug)]
enum Seg {
    Glob(Vec<u8>),
    Named(String),
    AnyMany,
}

#[derive(Clone, Debug)]
pub struct RoutePattern {
    method: Option<Vec<u8>>,
    segs: Vec<Seg>,
}

impl RoutePattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (method, path) = match s.split_once(' ') {
            Some((m, p)) if !m.starts_with('/') => {
                let m = m.trim().to_ascii_uppercase();
                ((m != "*").then(|| m.into_bytes()), p.trim())
            }
            _ => (None, s),
        };
        if !path.starts_with('/') {
            return Err(format!("route « {s} » : le chemin doit commencer par /"));
        }
        let mut segs = Vec::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            if part == "**" {
                segs.push(Seg::AnyMany);
            } else if part.starts_with('{') && part.ends_with('}') && part.len() > 2 {
                segs.push(Seg::Named(part[1..part.len() - 1].to_string()));
            } else {
                segs.push(Seg::Glob(part.as_bytes().to_vec()));
            }
        }
        Ok(RoutePattern { method, segs })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.segs.iter().filter_map(|s| match s {
            Seg::Named(n) => Some(n.as_str()),
            _ => None,
        })
    }

    /// Correspondance exacte du chemin (les `/` doublés sont ignorés). Les segments
    /// nommés sont ajoutés à `caps` avec leur position dans `line`.
    pub fn matches<'p>(&'p self, line: &[u8], req: &Request, caps: &mut Vec<(&'p str, (usize, usize))>) -> bool {
        if let Some(m) = &self.method {
            match req.method {
                Some((s, e)) if line[s..e] == m[..] => {}
                _ => return false,
            }
        }
        let mut path = Vec::new();
        let (ps, pe) = req.path;
        let mut i = ps;
        while i < pe {
            if line[i] == b'/' {
                i += 1;
                continue;
            }
            let s = i;
            while i < pe && line[i] != b'/' {
                i += 1;
            }
            path.push((s, i));
        }
        let mark = caps.len();
        let ok = match_segs(&self.segs, &path, line, caps);
        if !ok {
            caps.truncate(mark);
        }
        ok
    }
}

fn match_segs<'p>(segs: &'p [Seg], path: &[(usize, usize)], line: &[u8], caps: &mut Vec<(&'p str, (usize, usize))>) -> bool {
    let Some(first) = segs.first() else { return path.is_empty() };
    match first {
        Seg::AnyMany => (0..=path.len()).any(|k| {
            let mark = caps.len();
            let ok = match_segs(&segs[1..], &path[k..], line, caps);
            if !ok {
                caps.truncate(mark);
            }
            ok
        }),
        Seg::Glob(g) => !path.is_empty() && glob_match(g, &line[path[0].0..path[0].1]) && match_segs(&segs[1..], &path[1..], line, caps),
        Seg::Named(n) => {
            if path.is_empty() {
                return false;
            }
            caps.push((n.as_str(), path[0]));
            match_segs(&segs[1..], &path[1..], line, caps)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(line: &[u8]) -> Option<(String, String)> {
        find_request(line, 0).map(|r| {
            (
                r.method.map(|(s, e)| String::from_utf8_lossy(&line[s..e]).into_owned()).unwrap_or_default(),
                String::from_utf8_lossy(&line[r.path.0..r.path.1]).into_owned(),
            )
        })
    }

    #[test]
    fn finds_requests() {
        assert_eq!(req(b"in GET /api/ping"), Some(("GET".into(), "/api/ping".into())));
        assert_eq!(req(b"Sent 200 in 26ms\tGET /api/banishment/planification"), Some(("GET".into(), "/api/banishment/planification".into())));
        assert_eq!(req(b"[services@2001:41d0::1][Elixir.Api][#PID<0.1.2>] POST //api/user/M0000001?x=1"), Some(("POST".into(), "//api/user/M0000001".into())));
        assert_eq!(req(b"/api/order"), Some(("".into(), "/api/order".into())));
        assert_eq!(req(b"Error processing PREPROD/ECOM/x.xml in puller:"), None);
        assert_eq!(req(b"read /etc/hosts failed"), None);
    }

    fn m(pattern: &str, line: &[u8]) -> Option<Vec<(String, String)>> {
        let p = RoutePattern::parse(pattern).unwrap();
        let r = find_request(line, 0)?;
        let mut caps = Vec::new();
        p.matches(line, &r, &mut caps)
            .then(|| caps.iter().map(|(n, (s, e))| (n.to_string(), String::from_utf8_lossy(&line[*s..*e]).into_owned())).collect())
    }

    #[test]
    fn matches_routes() {
        assert_eq!(m("/api/ping", b"in GET /api/ping"), Some(vec![]));
        assert_eq!(m("GET /api/ping", b"in POST /api/ping"), None);
        assert_eq!(m("/api/ping", b"in GET /api/ping/x"), None);
        assert_eq!(m("/api/ping/**", b"in GET /api/ping/x/y"), Some(vec![]));
        assert_eq!(
            m("/api/etam_admin/{v}", b"in GET //api/etam_admin/jean.dupont@example.com"),
            Some(vec![("v".into(), "jean.dupont@example.com".into())])
        );
        assert_eq!(
            m("/riak/{bucket}/{key}", b"GET //riak/etam_sb_etam_admin/k1"),
            Some(vec![("bucket".into(), "etam_sb_etam_admin".into()), ("key".into(), "k1".into())])
        );
        assert_eq!(m("/api/{v}/**", b"GET /api/M0000001/a/b"), Some(vec![("v".into(), "M0000001".into())]));
        assert_eq!(m("/**/*.php", b"GET /a/b/index.php"), Some(vec![]));
    }
}

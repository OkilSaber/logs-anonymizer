//! `haproxy.log` : HAProxy via syslog.
//!
//! Chaque ligne physique est `<host>␠␠<ISO8601> <host> haproxy[<pid>]: <payload>` et forme
//! une entrée à elle seule. Trois payloads sont reconnus :
//!
//! - HTTP : `<ip>:<port> [<date>] <frontend> <backend>/<server> tls[…] t[…] c[<status>] sz[…]
//!   <req_cookie> <resp_cookie> <état> <conns> <files> hds[…] req["<MÉTHODE> <uri> <proto>"]` ;
//! - TCP : `<ip>:<port> [<date>] <frontend> <backend>/<server> <Tw/Tc/Tt> <octets> <état> <conns> <files>` ;
//! - erreur TLS : `<ip>:<port> [<date>] <frontend>/<n>: SSL handshake failure`.
//!
//! Tout le reste est une entrée `Other` : elle garde les champs lus avant l'écart et
//! passe par les détecteurs comme les autres.

use super::{frame_syslog, Format, FormatKind, Framed, LineClass};
use crate::entry::EntryKind;
use crate::http::Request;
use memchr::{memchr, memmem, memrchr};

/// Plage d'octets dans la ligne d'en-tête.
pub type Range = (usize, usize);

/// Champs lisibles par [`Format::field`], donc utilisables dans `where`.
pub const FIELDS: &[&str] =
    &["client_ip", "client_port", "frontend", "backend", "server", "status", "req_cookie", "resp_cookie", "termination", "request"];

/// Champs d'un payload HAProxy. Une ligne qui s'écarte du format garde ceux lus jusque-là.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub kind: EntryKind,
    /// Le port suit le dernier `:` : `2001:41d0:9a:aa0::2:65004` → `2001:41d0:9a:aa0::2`.
    pub client_ip: Option<Range>,
    pub client_port: Option<Range>,
    /// Sans le `~` final, qui marque TLS.
    pub frontend: Option<Range>,
    pub backend: Option<Range>,
    /// `<NOSRV>` quand aucun serveur n'a été choisi.
    pub server: Option<Range>,
    pub status: Option<Range>,
    /// Cookies capturés, `-` compris.
    pub req_cookie: Option<Range>,
    pub resp_cookie: Option<Range>,
    pub termination: Option<Range>,
    /// Contenu de `hds[…]`.
    pub hds: Option<Range>,
    /// Contenu de `req["…"]` : `GET /x HTTP/1.1` ou `<BADREQ>`.
    pub request: Option<Range>,
}

impl Line {
    fn other() -> Self {
        Line {
            kind: EntryKind::Other,
            client_ip: None,
            client_port: None,
            frontend: None,
            backend: None,
            server: None,
            status: None,
            req_cookie: None,
            resp_cookie: None,
            termination: None,
            hds: None,
            request: None,
        }
    }

    pub fn field(&self, name: &str) -> Option<Range> {
        match name {
            "client_ip" => self.client_ip,
            "client_port" => self.client_port,
            "frontend" => self.frontend,
            "backend" => self.backend,
            "server" => self.server,
            "status" => self.status,
            "req_cookie" => self.req_cookie,
            "resp_cookie" => self.resp_cookie,
            "termination" => self.termination,
            "request" => self.request,
            _ => None,
        }
    }
}

/// Longueur de `<ISO8601> <host> haproxy[<pid>]: ` en tête de contenu ; 0 s'il est absent.
pub fn syslog_header_len(c: &[u8]) -> usize {
    // `YYYY-MM-DDTHH:MM:SS…`
    if c.len() < 20 || !c[..4].iter().all(u8::is_ascii_digit) || c[4] != b'-' || c[10] != b'T' {
        return 0;
    }
    let space = |from: usize| memchr(b' ', &c[from..]).map(|o| from + o);
    let Some(date_end) = space(0) else { return 0 };
    let Some(host_end) = space(date_end + 1) else { return 0 };
    let Some(tag_end) = space(host_end + 1) else { return 0 };
    let tag = &c[host_end + 1..tag_end];
    let pid = tag.strip_prefix(b"haproxy[").and_then(|t| t.strip_suffix(b"]:"));
    match pid {
        Some(pid) if !pid.is_empty() && pid.iter().all(u8::is_ascii_digit) => tag_end + 1,
        _ => 0,
    }
}

struct Cursor<'a> {
    h: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    /// Mot suivant, jusqu'à l'espace (consommé). `None` en fin de ligne ou sur un mot vide.
    fn word(&mut self) -> Option<Range> {
        let s = self.pos;
        if s >= self.h.len() {
            return None;
        }
        let e = memchr(b' ', &self.h[s..]).map_or(self.h.len(), |o| s + o);
        if e == s {
            return None;
        }
        self.pos = (e + 1).min(self.h.len());
        Some((s, e))
    }

    /// Mot `<tag>…]` : rend la plage entre les crochets.
    fn bracketed(&mut self, tag: &[u8]) -> Option<Range> {
        let (s, e) = self.word()?;
        let w = &self.h[s..e];
        (w.len() > tag.len() && w.starts_with(tag) && w[w.len() - 1] == b']').then_some((s + tag.len(), e - 1))
    }

    /// Mot fait de nombres séparés par exactement `slashes` barres : `1/1/0/0/0`, `-1/-1/46`, `+6972`.
    fn numbers(&mut self, slashes: usize) -> Option<Range> {
        let (s, e) = self.word()?;
        let w = &self.h[s..e];
        let ok = w.iter().all(|b| b.is_ascii_digit() || matches!(b, b'/' | b'-' | b'+')) && w.iter().filter(|b| **b == b'/').count() == slashes;
        ok.then_some((s, e))
    }
}

/// Lit le payload HAProxy qui commence à `from` dans la ligne d'en-tête `h`. Ne panique
/// jamais : une ligne inattendue rend `kind = Other` et les champs lus avant l'écart.
pub fn parse(h: &[u8], from: usize) -> Line {
    let mut l = Line::other();
    let h = h.trim_ascii_end();
    let mut c = Cursor { h, pos: from.min(h.len()) };

    // <client_ip>:<port> [<accept_date>]
    let Some((s, e)) = c.word() else { return l };
    let Some(colon) = memrchr(b':', &h[s..e]).map(|o| s + o) else { return l };
    let ip_like = colon > s && h[s..colon].iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_'));
    let port_like = colon + 1 < e && h[colon + 1..e].iter().all(u8::is_ascii_digit);
    if !ip_like || !port_like {
        return l;
    }
    let Some((ds, de)) = c.word() else { return l };
    if h[ds] != b'[' || h[de - 1] != b']' {
        return l;
    }
    l.client_ip = Some((s, colon));
    l.client_port = Some((colon + 1, e));

    // <frontend>, ou `<frontend>/<n>: <message>` pour une erreur de connexion.
    let Some((fs, fe)) = c.word() else { return l };
    if h[fe - 1] == b':' {
        if let Some(slash) = memrchr(b'/', &h[fs..fe - 1]).map(|o| fs + o) {
            if slash > fs && slash + 2 < fe && h[slash + 1..fe - 1].iter().all(u8::is_ascii_digit) {
                l.frontend = Some((fs, slash));
                if memmem::find(&h[c.pos..], b"SSL handshake").is_some() {
                    l.kind = EntryKind::TlsError;
                }
            }
        }
        return l;
    }
    let name_end = if h[fe - 1] == b'~' { fe - 1 } else { fe };
    if name_end == fs {
        return l;
    }
    l.frontend = Some((fs, name_end));

    // <backend>/<server>
    let Some((bs, be)) = c.word() else { return l };
    let Some(slash) = memrchr(b'/', &h[bs..be]).map(|o| bs + o) else { return l };
    if slash == bs || slash + 1 == be {
        return l;
    }
    l.backend = Some((bs, slash));
    l.server = Some((slash + 1, be));

    if h[c.pos..].starts_with(b"tls[") {
        parse_http(&mut c, &mut l);
    } else {
        parse_tcp(&mut c, &mut l);
    }
    l
}

/// `tls[…] t[…] c[<status>] sz[…] <req_cookie> <resp_cookie> <état> <conns> <files> hds[…] req["…"]`
fn parse_http(c: &mut Cursor<'_>, l: &mut Line) -> Option<()> {
    c.bracketed(b"tls[")?;
    c.bracketed(b"t[")?;
    l.status = Some(c.bracketed(b"c[")?);
    c.bracketed(b"sz[")?;
    l.req_cookie = Some(c.word()?);
    l.resp_cookie = Some(c.word()?);
    l.termination = Some(c.word()?);
    c.numbers(4)?;
    c.numbers(1)?;
    // Les en-têtes capturés peuvent contenir des espaces : la requête commence au
    // premier `] req["` et va jusqu'au bout de la ligne.
    let h = c.h;
    let hds = c.pos + 4;
    if !h[c.pos..].starts_with(b"hds[") {
        return None;
    }
    const SEP: &[u8] = b"] req[\"";
    let sep = hds + memmem::find(&h[hds..], SEP)?;
    l.hds = Some((hds, sep));
    let rs = sep + SEP.len();
    // Une ligne tronquée par syslog n'a pas son `"]` final.
    let re = if h[rs..].ends_with(b"\"]") { h.len() - 2 } else { h.len() };
    l.request = Some((rs, re));
    l.kind = EntryKind::Http;
    Some(())
}

/// `<Tw/Tc/Tt> <octets> <état> <conns> <files>`
fn parse_tcp(c: &mut Cursor<'_>, l: &mut Line) -> Option<()> {
    c.numbers(2)?;
    c.numbers(0)?;
    l.termination = Some(c.word()?);
    c.numbers(4)?;
    c.numbers(1)?;
    if c.pos >= c.h.len() {
        l.kind = EntryKind::Tcp;
    }
    Some(())
}

/// Requête du contenu de `req["…"]` : `MÉTHODE uri [HTTP/x]`. L'URI va jusqu'au
/// protocole, espaces compris ; une forme absolue (`http://host/chemin`) rend son chemin.
/// `<BADREQ>` n'est pas une requête.
pub fn request_of(h: &[u8], (s, e): Range) -> Option<Request> {
    let sp = s + memchr(b' ', &h[s..e])?;
    if sp == s || !h[s..sp].iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    let us = sp + 1;
    let ue = match memrchr(b' ', &h[us..e]) {
        Some(o) if h[us + o + 1..e].starts_with(b"HTTP/") => us + o,
        _ => e,
    };
    let ps = if h[us..ue].first() == Some(&b'/') {
        us
    } else {
        let authority = us + memmem::find(&h[us..ue], b"://")? + 3;
        authority + memchr(b'/', &h[authority..ue])?
    };
    let (pe, query) = match memchr(b'?', &h[ps..ue]) {
        Some(q) => (ps + q, Some((ps + q + 1, ue))),
        None => (ue, None),
    };
    Some(Request { method: Some((s, sp)), path: (ps, pe), query })
}

/// IP inscrite dans un nom de frontend ou de backend : `node-public_ipv4-51_75_10_28-443`
/// → `51_75_10_28`, `node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80` → l'IPv6.
pub fn ip_in_name(h: &[u8], (s, e): Range) -> Option<Range> {
    let mut i = s;
    while i < e {
        let j = memchr(b'-', &h[i..e]).map_or(e, |o| i + o);
        let seg = &h[i..j];
        let candidate = memchr(b'_', seg).is_some() && seg.iter().all(|b| b.is_ascii_hexdigit() || *b == b'_');
        if candidate && crate::netaddr::parse_loose(seg).is_some() {
            return Some((i, j));
        }
        i = j + 1;
    }
    None
}

pub struct HaproxySyslog {
    /// Le contenu d'une entrée est le payload seul.
    pub compact_header: bool,
}

impl Format for HaproxySyslog {
    fn kind(&self) -> FormatKind {
        FormatKind::HaproxySyslog
    }

    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a> {
        let mut f = frame_syslog(line);
        if self.compact_header {
            f.content = &f.content[syslog_header_len(f.content)..];
        }
        f
    }

    fn classify(&self, c: &[u8]) -> LineClass {
        if c.iter().all(|b| b.is_ascii_whitespace()) {
            return LineClass::Separator;
        }
        LineClass::Standalone(parse(c, syslog_header_len(c)).kind)
    }

    /// Début du payload : 0 quand l'en-tête syslog a été retiré (`compact_header`) ou manque.
    fn message_start(&self, header: &[u8]) -> usize {
        syslog_header_len(header)
    }

    fn request(&self, header: &[u8]) -> Option<Request> {
        request_of(header, parse(header, syslog_header_len(header)).request?)
    }

    fn field_names(&self) -> &'static [&'static str] {
        FIELDS
    }

    fn field<'a>(&self, header: &'a [u8], name: &str) -> Option<&'a [u8]> {
        let (s, e) = parse(header, syslog_header_len(header)).field(name)?;
        Some(&header[s..e])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble::{AssembleOptions, Assembler};
    use crate::entry::Entry;
    use std::sync::Arc;

    const SYSLOG: &str = "2026-11-09T00:00:06+00:00 etam-admin01.etam-sb.kbrw.fr haproxy[227]: ";
    const HTTP: &str = "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] node-public_ipv4-51_75_10_28-443~ etam_sb_admin-local_ipv6-8080/etam-admin01 tls[TLSv1.3/TLS_AES_256_GCM_SHA384/28] t[0/0/0/1/1] c[200] sz[174] - - ---- 1/1/0/0/0 0/0 hds[{etam-sb-etam-admin.kbrw.fr|}] req[\"GET /api/ping HTTP/1.1\"]";
    const HTTP_V6: &str = "2001:41d0:9a:aa0::2:65004 [09/Nov/2026:02:11:25.576] node-local_ipv6-2001_41d0_9a_a11_8200_8201_0_1-80 riakn-local_ipv6-80/riakn04 tls[-/-/0] t[0/0/0/5/5] c[200] sz[2428] - - ---- 2/2/0/0/0 0/0 hds[{}] req[\"GET /search/query/preprod_jar_orders_refund?q=last_notification:[*+TO+NOW-1DAY]&wt=json HTTP/1.1\"]";
    const BADREQ: &str = "198.51.100.74:43078 [09/Nov/2026:00:10:02.290] node-public_ipv4-188_165_78_170-443~ node-public_ipv4-188_165_78_170-443/<NOSRV> tls[TLSv1.3/TLS_CHACHA20_POLY1305_SHA256/26] t[-1/-1/-1/-1/46] c[400] sz[0] - - CR-- 1/1/0/0/0 0/0 hds[] req[\"<BADREQ>\"]";
    const TCP: &str = "198.51.100.178:60268 [09/Nov/2026:00:00:32.160] sftp-frontend-ipv4 sftp-backend-ipv6/primary 1/0/60679 6972 sD 1/1/0/0/0 0/0";
    const TLS: &str = "198.51.100.153:46054 [09/Nov/2026:00:06:56.849] node-public_ipv4-188_165_78_170-443/1: SSL handshake failure";

    fn fields(h: &str) -> Vec<(&'static str, &str)> {
        let l = parse(h.as_bytes(), syslog_header_len(h.as_bytes()));
        FIELDS.iter().filter_map(|f| l.field(f).map(|(s, e)| (*f, &h[s..e]))).collect()
    }

    fn kind(h: &str) -> EntryKind {
        parse(h.as_bytes(), syslog_header_len(h.as_bytes())).kind
    }

    #[test]
    fn syslog_header_is_recognised() {
        assert_eq!(syslog_header_len(SYSLOG.as_bytes()), SYSLOG.len());
        assert_eq!(syslog_header_len(format!("{SYSLOG}{HTTP}").as_bytes()), SYSLOG.len());
        // Payload seul, autre programme, pid absent, ligne coupée.
        assert_eq!(syslog_header_len(HTTP.as_bytes()), 0);
        assert_eq!(syslog_header_len(HTTP_V6.as_bytes()), 0);
        assert_eq!(syslog_header_len(b"2026-11-09T00:00:06+00:00 h.kbrw.fr sshd[227]: Accepted"), 0);
        assert_eq!(syslog_header_len(b"2026-11-09T00:00:06+00:00 h.kbrw.fr haproxy[]: x"), 0);
        assert_eq!(syslog_header_len(b"2026-11-09T00:00:06+00:00 h.kbrw.fr haproxy[227]:"), 0);
        assert_eq!(syslog_header_len(b"2026-11-09T00:00:06+00:00"), 0);
        assert_eq!(syslog_header_len(b""), 0);
    }

    #[test]
    fn http_fields() {
        assert_eq!(kind(HTTP), EntryKind::Http);
        assert_eq!(
            fields(HTTP),
            vec![
                ("client_ip", "198.51.100.65"),
                ("client_port", "40461"),
                ("frontend", "node-public_ipv4-51_75_10_28-443"),
                ("backend", "etam_sb_admin-local_ipv6-8080"),
                ("server", "etam-admin01"),
                ("status", "200"),
                ("req_cookie", "-"),
                ("resp_cookie", "-"),
                ("termination", "----"),
                ("request", "GET /api/ping HTTP/1.1"),
            ]
        );
        // Avec l'en-tête syslog, les mêmes champs.
        let full = format!("{SYSLOG}{HTTP}");
        assert_eq!(kind(&full), EntryKind::Http);
        assert_eq!(fields(&full), fields(HTTP));
    }

    #[test]
    fn ipv6_client_port_follows_the_last_colon() {
        assert_eq!(kind(HTTP_V6), EntryKind::Http);
        let f = fields(HTTP_V6);
        assert_eq!(f[0], ("client_ip", "2001:41d0:9a:aa0::2"));
        assert_eq!(f[1], ("client_port", "65004"));
        assert_eq!(f[2], ("frontend", "node-local_ipv6-2001_41d0_9a_a11_8200_8201_0_1-80"));
        // Sans TLS : `tls[-/-/0]`.
        assert_eq!(f[5], ("status", "200"));
        // Un port court donnerait une IPv6 valide en entier : le dernier `:` l'emporte quand même.
        let short = HTTP_V6.replace(":65004 ", ":6500 ");
        assert_eq!(fields(&short)[0], ("client_ip", "2001:41d0:9a:aa0::2"));
        assert_eq!(fields(&short)[1], ("client_port", "6500"));
        let full = "2001:41d0:9a:a10:b00:6100:0:1:56473 [09/Nov/2026:07:27:23.960] f b/s tls[-/-/0] t[0/0/0/8/8] c[200] sz[2159] - - ---- 2/2/1/1/0 0/0 hds[{}] req[\"GET / HTTP/1.1\"]";
        assert_eq!(fields(full)[0], ("client_ip", "2001:41d0:9a:a10:b00:6100:0:1"));
    }

    #[test]
    fn badreq_nosrv_and_negative_timers() {
        assert_eq!(kind(BADREQ), EntryKind::Http);
        let f = fields(BADREQ);
        assert!(f.contains(&("backend", "node-public_ipv4-188_165_78_170-443")));
        assert!(f.contains(&("server", "<NOSRV>")));
        assert!(f.contains(&("status", "400")));
        assert!(f.contains(&("termination", "CR--")));
        assert!(f.contains(&("request", "<BADREQ>")));
        let l = parse(BADREQ.as_bytes(), 0);
        assert_eq!(l.hds.map(|(s, e)| &BADREQ[s..e]), Some(""));
        assert_eq!(request_of(BADREQ.as_bytes(), l.request.unwrap()), None);
    }

    #[test]
    fn captured_headers() {
        let hds = |h: &str| parse(h.as_bytes(), 0).hds.map(|(s, e)| h[s..e].to_string());
        assert_eq!(hds(HTTP).as_deref(), Some("{etam-sb-etam-admin.kbrw.fr|}"));
        assert_eq!(hds(HTTP_V6).as_deref(), Some("{}"));
        assert_eq!(hds(BADREQ).as_deref(), Some(""));
        let ip = HTTP.replace("{etam-sb-etam-admin.kbrw.fr|}", "{51.75.11.123:80|}");
        assert_eq!(hds(&ip).as_deref(), Some("{51.75.11.123:80|}"));
        // Un en-tête capturé peut contenir des espaces.
        let ua = HTTP.replace("{etam-sb-etam-admin.kbrw.fr|}", "{h.kbrw.fr|Mozilla/5.0 (X11; Linux)}");
        assert_eq!(kind(&ua), EntryKind::Http);
        assert_eq!(hds(&ua).as_deref(), Some("{h.kbrw.fr|Mozilla/5.0 (X11; Linux)}"));
        assert!(fields(&ua).contains(&("request", "GET /api/ping HTTP/1.1")));
    }

    #[test]
    fn tcp_line() {
        assert_eq!(kind(TCP), EntryKind::Tcp);
        assert_eq!(
            fields(TCP),
            vec![
                ("client_ip", "198.51.100.178"),
                ("client_port", "60268"),
                ("frontend", "sftp-frontend-ipv4"),
                ("backend", "sftp-backend-ipv6"),
                ("server", "primary"),
                ("termination", "sD"),
            ]
        );
        // Du texte en plus : ce n'est plus la forme TCP.
        assert_eq!(kind(&format!("{TCP} extra")), EntryKind::Other);
    }

    #[test]
    fn tls_errors() {
        for msg in ["SSL handshake failure", "Timeout during SSL handshake", "Connection closed during SSL handshake"] {
            let line = TLS.replace("SSL handshake failure", msg);
            assert_eq!(kind(&line), EntryKind::TlsError, "{msg}");
            assert_eq!(
                fields(&line),
                vec![("client_ip", "198.51.100.153"), ("client_port", "46054"), ("frontend", "node-public_ipv4-188_165_78_170-443")],
                "{msg}"
            );
        }
        // Même forme, autre message : l'entrée n'est pas une erreur TLS mais garde ses champs.
        let other = TLS.replace("SSL handshake failure", "Received something which does not look like a PROXY protocol header");
        assert_eq!(kind(&other), EntryKind::Other);
        assert_eq!(fields(&other).len(), 3);
    }

    #[test]
    fn malformed_lines_never_panic_and_are_other() {
        let cases: &[&str] = &[
            "",
            " ",
            "x",
            ":",
            "a:",
            ":1",
            "198.51.100.65:40461",
            "198.51.100.65:40461 ",
            "198.51.100.65:40461 [",
            "198.51.100.65:40461 []",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788]",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] ",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] ~",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f/1:",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] /1: SSL handshake failure",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f/: SSL handshake failure",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f /s",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[] t[] c[] sz[]",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[-/-/0] t[0/0/0/1/1] c[200] sz[1] - - ---- 1/1/0/0/0 0/0",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[-/-/0] t[0/0/0/1/1] c[200] sz[1] - - ---- 1/1/0/0/0 0/0 hds[",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[-/-/0] t[0/0/0/1/1] c[200] sz[1] - - ---- 1/1/0/0/0 0/0 hds[{}]",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s tls[-/-/0]  t[0/0/0/1/1] c[200]",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s 1/0 6972 sD 1/1/0/0/0 0/0",
            "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] f b/s 1/0/60679 6972 sD",
            "Proxy etam_sb_admin-local_ipv6-8080 started.",
            "Server riakn-local_ipv6-80/riakn03 is DOWN, reason: Layer4 timeout",
            "jean.dupont@example.com:25 [x] y",
            "\u{e9}\u{e8}:1 [\u{20ac}] \u{e0}",
        ];
        for c in cases {
            assert_eq!(kind(c), EntryKind::Other, "{c:?}");
            assert_eq!(kind(&format!("{SYSLOG}{c}")), EntryKind::Other, "{c:?}");
        }
        // Toutes les coupes d'une ligne valide, à chaque position.
        for line in [HTTP, HTTP_V6, BADREQ, TCP, TLS] {
            for cut in 0..line.len() {
                let _ = parse(&line.as_bytes()[..cut], 0);
                let _ = parse(line.as_bytes(), cut);
                let _ = syslog_header_len(&format!("{SYSLOG}{line}").as_bytes()[..cut.min(SYSLOG.len() + 5)]);
            }
        }
        // Une requête coupée par syslog reste une entrée HTTP, sans son `"]` final.
        let cut = &HTTP[..HTTP.len() - 12];
        assert_eq!(kind(cut), EntryKind::Http);
        assert!(fields(cut).contains(&("request", "GET /api/pin")));
    }

    #[test]
    fn requests() {
        let req = |h: &str| {
            let f = HaproxySyslog { compact_header: true };
            f.request(h.as_bytes()).map(|r| {
                let (ms, me) = r.method.unwrap();
                (h[ms..me].to_string(), h[r.path.0..r.path.1].to_string(), r.query.map(|(s, e)| h[s..e].to_string()))
            })
        };
        assert_eq!(req(HTTP), Some(("GET".into(), "/api/ping".into(), None)));
        assert_eq!(req(&format!("{SYSLOG}{HTTP}")), Some(("GET".into(), "/api/ping".into(), None)));
        assert_eq!(
            req(HTTP_V6),
            Some(("GET".into(), "/search/query/preprod_jar_orders_refund".into(), Some("q=last_notification:[*+TO+NOW-1DAY]&wt=json".into())))
        );
        assert_eq!(req(BADREQ), None);
        assert_eq!(req(TCP), None);
        assert_eq!(req(TLS), None);
        let with = |r: &str| HTTP.replace("GET /api/ping HTTP/1.1", r);
        // Sans protocole, URI avec espaces, forme absolue, méthode sans chemin.
        assert_eq!(req(&with("GET /x")), Some(("GET".into(), "/x".into(), None)));
        assert_eq!(req(&with("GET /a b?c=d e HTTP/1.1")), Some(("GET".into(), "/a b".into(), Some("c=d e".into()))));
        assert_eq!(req(&with("GET http://198.51.100.9/.env?x=1 HTTP/1.1")), Some(("GET".into(), "/.env".into(), Some("x=1".into()))));
        assert_eq!(req(&with("CONNECT example.com:443 HTTP/1.1")), None);
        assert_eq!(req(&with("OPTIONS * HTTP/1.0")), None);
        assert_eq!(req(&with("")), None);
        assert_eq!(req(&with("GET")), None);
    }

    #[test]
    fn named_fields_for_where() {
        let f = HaproxySyslog { compact_header: false };
        let line = format!("{SYSLOG}{BADREQ}");
        let get = |name: &str| f.field(line.as_bytes(), name).map(|v| String::from_utf8_lossy(v).into_owned());
        assert_eq!(get("status").as_deref(), Some("400"));
        assert_eq!(get("request").as_deref(), Some("<BADREQ>"));
        assert_eq!(get("server").as_deref(), Some("<NOSRV>"));
        assert_eq!(get("client_ip").as_deref(), Some("198.51.100.74"));
        assert_eq!(get("nope"), None);
        assert_eq!(f.field(TLS.as_bytes(), "status"), None);
        for name in f.field_names() {
            assert!(Line::other().field(name).is_none());
            assert!(parse(HTTP.as_bytes(), 0).field(name).is_some(), "{name}");
        }
    }

    #[test]
    fn ip_in_frontend_and_backend_names() {
        fn ip(name: &str) -> Option<&str> {
            ip_in_name(name.as_bytes(), (0, name.len())).map(|(s, e)| &name[s..e])
        }
        assert_eq!(ip("node-public_ipv4-51_75_10_28-443"), Some("51_75_10_28"));
        assert_eq!(ip("node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80"), Some("2001_41d0_9a_a10_b03_701_0_1"));
        assert_eq!(ip("etam_sb_admin-local_ipv6-8080"), None);
        assert_eq!(ip("sftp-frontend-ipv4"), None);
        assert_eq!(ip("riakn-local_ipv6-80"), None);
        assert_eq!(ip("a-300_1_1_1-80"), None);
        assert_eq!(ip(""), None);
    }

    fn assemble(compact: bool, input: &[u8]) -> Vec<Entry> {
        let mut a = Assembler::new(Arc::new(HaproxySyslog { compact_header: compact }), AssembleOptions::default());
        let mut out = Vec::new();
        for line in input.split(|b| *b == b'\n') {
            a.push_line(line, &mut out);
        }
        a.finish(&mut out);
        out
    }

    #[test]
    fn one_line_is_one_entry_with_crlf_and_compact_header() {
        let input = format!(
            "a.kbrw.fr  {SYSLOG}{HTTP}\r\nb.kbrw.fr  {SYSLOG}{TCP}\r\na.kbrw.fr  {SYSLOG}{TLS}\r\na.kbrw.fr  {SYSLOG}Proxy x started.\r\nnot a haproxy line\r\na.kbrw.fr  \r\n"
        );
        let e = assemble(true, input.as_bytes());
        assert_eq!(e.iter().map(|x| x.kind).collect::<Vec<_>>(), vec![EntryKind::Http, EntryKind::Tcp, EntryKind::TlsError, EntryKind::Other, EntryKind::Other]);
        assert_eq!(e.iter().map(|x| &*x.source).collect::<Vec<_>>(), vec!["a.kbrw.fr", "b.kbrw.fr", "a.kbrw.fr", "a.kbrw.fr", ""]);
        assert_eq!(e[0].text, HTTP.as_bytes());
        assert_eq!(e[1].text, TCP.as_bytes());
        assert_eq!(e[2].text, TLS.as_bytes());
        assert_eq!(e[3].text, b"Proxy x started.");
        assert_eq!(e[4].text, b"not a haproxy line");
        assert!(e.iter().all(|x| x.lines == 1 && x.level.is_none()));

        // Sans compact_header, l'en-tête syslog reste dans le contenu.
        let e = assemble(false, input.as_bytes());
        assert_eq!(e[0].kind, EntryKind::Http);
        assert_eq!(e[0].text, format!("{SYSLOG}{HTTP}").as_bytes());
        assert_eq!(e[2].kind, EntryKind::TlsError);
        let f = HaproxySyslog { compact_header: false };
        assert_eq!(f.message_start(&e[0].text), SYSLOG.len());
    }
}

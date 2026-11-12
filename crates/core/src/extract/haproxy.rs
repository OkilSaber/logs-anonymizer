//! Champs d'une ligne HAProxy, aux chemins `haproxy.<champ>`.
//!
//! `haproxy.frontend.ip` et `haproxy.backend.ip` couvrent l'IP inscrite dans le nom
//! (`node-public_ipv4-51_75_10_28-443~` → `51_75_10_28`). Un cookie capturé absent (`-`)
//! ne donne pas de valeur. `haproxy.hds.<i>` numérote les en-têtes capturés, vides compris.

use super::{ExtractorId, Spans, ValueKind};
use crate::format::haproxy::{ip_in_name, parse, syslog_header_len, Range};

fn leaf(sp: &mut Spans, name: &[u8], range: Option<Range>) {
    if let Some((s, e)) = range {
        let mark = sp.push_seg(name);
        sp.leaf(s, e, ExtractorId::Haproxy, ValueKind::Raw, false);
        sp.pop_seg(mark);
    }
}

/// Nom de frontend ou de backend, puis l'IP qu'il contient.
fn name(sp: &mut Spans, h: &[u8], seg: &[u8], range: Option<Range>) {
    let Some((s, e)) = range else { return };
    let mark = sp.push_seg(seg);
    sp.leaf(s, e, ExtractorId::Haproxy, ValueKind::Raw, false);
    leaf(sp, b"ip", ip_in_name(h, (s, e)));
    sp.pop_seg(mark);
}

/// Écriture décimale de `n`, sans allocation.
fn decimal(mut n: usize, buf: &mut [u8; 20]) -> &[u8] {
    let mut at = buf.len();
    loop {
        at -= 1;
        buf[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return &buf[at..];
        }
    }
}

/// `{a|b}`, `{a|b} {c}` ou `a|b` : une valeur par en-tête non vide, numérotée dans l'ordre.
fn captured_headers(sp: &mut Spans, h: &[u8], (s, e): Range) {
    let mark = sp.push_seg(b"hds");
    let mut buf = [0u8; 20];
    let mut index = 0usize;
    let mut start = s;
    for (i, b) in (s..e).zip(&h[s..e]) {
        match b {
            b'{' => start = i + 1,
            b'|' | b'}' => {
                leaf(sp, decimal(index, &mut buf), Some((start, i)));
                index += 1;
                // Entre deux groupes `{…} {…}`, rien n'est une valeur.
                start = if *b == b'}' { e } else { i + 1 };
            }
            _ => {}
        }
    }
    if start < e {
        leaf(sp, decimal(index, &mut buf), Some((start, e)));
    }
    sp.pop_seg(mark);
}

pub fn scan(text: &[u8], header_len: usize, sp: &mut Spans) {
    let h = &text[..header_len];
    let l = parse(h, syslog_header_len(h));
    if l.client_ip.is_none() {
        return;
    }
    let root = sp.push_seg(b"haproxy");
    leaf(sp, b"client_ip", l.client_ip);
    leaf(sp, b"client_port", l.client_port);
    name(sp, h, b"frontend", l.frontend);
    name(sp, h, b"backend", l.backend);
    leaf(sp, b"server", l.server);
    leaf(sp, b"status", l.status);
    let cookie = |r: Option<Range>| r.filter(|&(s, e)| &h[s..e] != b"-");
    leaf(sp, b"req_cookie", cookie(l.req_cookie));
    leaf(sp, b"resp_cookie", cookie(l.resp_cookie));
    if let Some(r) = l.hds {
        captured_headers(sp, h, r);
    }
    leaf(sp, b"request", l.request);
    sp.pop_seg(root);
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};

    fn extract(text: &str) -> Vec<(String, String)> {
        let mut sp = Spans::default();
        let set = ExtractorSet { haproxy: true, http_request: false, ..ExtractorSet::default() };
        run(text.as_bytes(), text.len(), None, &set, &mut sp);
        dump(text.as_bytes(), &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn http_with_public_ipv4_and_tls() {
        let text = "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] node-public_ipv4-51_75_10_28-443~ etam_sb_admin-local_ipv6-8080/etam-admin01 tls[TLSv1.3/TLS_AES_256_GCM_SHA384/28] t[0/0/0/1/1] c[200] sz[174] - - ---- 1/1/0/0/0 0/0 hds[{etam-sb-etam-admin.kbrw.fr|}] req[\"GET /api/ping HTTP/1.1\"]";
        assert_eq!(
            extract(text),
            vec![
                s("haproxy.client_ip", "198.51.100.65"),
                s("haproxy.client_port", "40461"),
                s("haproxy.frontend", "node-public_ipv4-51_75_10_28-443"),
                s("haproxy.frontend.ip", "51_75_10_28"),
                s("haproxy.backend", "etam_sb_admin-local_ipv6-8080"),
                s("haproxy.server", "etam-admin01"),
                s("haproxy.status", "200"),
                s("haproxy.hds.0", "etam-sb-etam-admin.kbrw.fr"),
                s("haproxy.request", "GET /api/ping HTTP/1.1"),
            ]
        );
    }

    #[test]
    fn syslog_header_ipv6_client_and_captured_cookies() {
        let text = "2026-11-09T07:27:23+00:00 etam-sb-user-access01.etam-sb.kbrw.fr haproxy[1060495]: 2001:41d0:9a:a10:b00:6100:0:1:56473 [09/Nov/2026:07:27:23.960] node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80 etam_sb_user-local_ipv6-8080/etam-user01 tls[-/-/0] t[0/0/0/8/8] c[200] sz[2159] sid=abc123 - ---- 2/2/1/1/0 0/0 hds[{}] req[\"GET //api/x HTTP/1.1\"]";
        assert_eq!(
            extract(text),
            vec![
                s("haproxy.client_ip", "2001:41d0:9a:a10:b00:6100:0:1"),
                s("haproxy.client_port", "56473"),
                s("haproxy.frontend", "node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80"),
                s("haproxy.frontend.ip", "2001_41d0_9a_a10_b03_701_0_1"),
                s("haproxy.backend", "etam_sb_user-local_ipv6-8080"),
                s("haproxy.server", "etam-user01"),
                s("haproxy.status", "200"),
                s("haproxy.req_cookie", "sid=abc123"),
                s("haproxy.request", "GET //api/x HTTP/1.1"),
            ]
        );
    }

    #[test]
    fn nosrv_badreq_and_backend_ip() {
        let text = "198.51.100.74:43078 [09/Nov/2026:00:10:02.290] node-public_ipv4-188_165_78_170-443~ node-public_ipv4-188_165_78_170-443/<NOSRV> tls[TLSv1.3/TLS_CHACHA20_POLY1305_SHA256/26] t[-1/-1/-1/-1/46] c[400] sz[0] - - CR-- 1/1/0/0/0 0/0 hds[] req[\"<BADREQ>\"]";
        assert_eq!(
            extract(text),
            vec![
                s("haproxy.client_ip", "198.51.100.74"),
                s("haproxy.client_port", "43078"),
                s("haproxy.frontend", "node-public_ipv4-188_165_78_170-443"),
                s("haproxy.frontend.ip", "188_165_78_170"),
                s("haproxy.backend", "node-public_ipv4-188_165_78_170-443"),
                s("haproxy.backend.ip", "188_165_78_170"),
                s("haproxy.server", "<NOSRV>"),
                s("haproxy.status", "400"),
                s("haproxy.request", "<BADREQ>"),
            ]
        );
    }

    #[test]
    fn captured_header_forms() {
        let hds = |h: &str| {
            let text = format!("198.51.100.65:1 [d] f b/s tls[-/-/0] t[0/0/0/1/1] c[200] sz[1] - - ---- 1/1/0/0/0 0/0 hds[{h}] req[\"GET / HTTP/1.1\"]");
            extract(&text).into_iter().filter(|(p, _)| p.starts_with("haproxy.hds")).collect::<Vec<_>>()
        };
        assert_eq!(hds(""), vec![]);
        assert_eq!(hds("{}"), vec![]);
        assert_eq!(hds("{etam-sb-etam-admin.kbrw.fr|}"), vec![s("haproxy.hds.0", "etam-sb-etam-admin.kbrw.fr")]);
        assert_eq!(hds("{51.75.11.123:80|}"), vec![s("haproxy.hds.0", "51.75.11.123:80")]);
        assert_eq!(hds("{|Mozilla/5.0 (X11)}"), vec![s("haproxy.hds.1", "Mozilla/5.0 (X11)")]);
        assert_eq!(hds("{a|b} {c}"), vec![s("haproxy.hds.0", "a"), s("haproxy.hds.1", "b"), s("haproxy.hds.2", "c")]);
        assert_eq!(hds("a|b"), vec![s("haproxy.hds.0", "a"), s("haproxy.hds.1", "b")]);
        let many = (0..12).map(|i| format!("h{i}")).collect::<Vec<_>>().join("|");
        assert_eq!(hds(&format!("{{{many}}}")).last(), Some(&s("haproxy.hds.11", "h11")));
    }

    #[test]
    fn tcp_tls_error_and_foreign_lines() {
        assert_eq!(
            extract("198.51.100.178:60268 [09/Nov/2026:00:00:32.160] sftp-frontend-ipv4 sftp-backend-ipv6/primary 1/0/60679 6972 sD 1/1/0/0/0 0/0"),
            vec![
                s("haproxy.client_ip", "198.51.100.178"),
                s("haproxy.client_port", "60268"),
                s("haproxy.frontend", "sftp-frontend-ipv4"),
                s("haproxy.backend", "sftp-backend-ipv6"),
                s("haproxy.server", "primary"),
            ]
        );
        assert_eq!(
            extract("198.51.100.153:46054 [09/Nov/2026:00:06:56.849] node-public_ipv4-188_165_78_170-443/1: Timeout during SSL handshake"),
            vec![
                s("haproxy.client_ip", "198.51.100.153"),
                s("haproxy.client_port", "46054"),
                s("haproxy.frontend", "node-public_ipv4-188_165_78_170-443"),
                s("haproxy.frontend.ip", "188_165_78_170"),
            ]
        );
        assert_eq!(extract("Proxy etam_sb_admin-local_ipv6-8080 started."), vec![]);
        assert_eq!(extract("09:39:05.203 [info]  in GET /api/x"), vec![]);
        assert_eq!(extract(""), vec![]);
    }
}

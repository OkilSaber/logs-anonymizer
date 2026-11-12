//! Formats `haproxy_syslog` et `lager_syslog` de bout en bout : routes, conditions `where`,
//! extracteurs activés par le template, lignes inattendues.

// Ces tests s'appuient sur les templates et le corpus, qui ne font pas partie du dépôt.
#![cfg(logano_templates)]

use logano_core::pipeline::{run, sandbox, RunOptions};
use logano_core::template::testing::TEST_KEY;
use logano_core::{Engine, EngineOptions, Library, Stats};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

const HEAD: &str = "[template]\nid='t/x'\nname='x'\nversion='1.0.0'\nschema_version=1\n";

fn engine(body: &str) -> Engine {
    let mut lib = Library::builtin();
    lib.add_str(&format!("{HEAD}{body}")).unwrap();
    Engine::new(Arc::new(lib.compile("t/x").unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap()
}

fn anonymize(engine: &Engine, input: &str) -> (String, Stats) {
    let mut out = Vec::new();
    let stats = run(input.as_bytes(), engine, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    (String::from_utf8(out).unwrap(), stats)
}

fn filter_hits(engine: &Engine, stats: &Stats, id: &str) -> u64 {
    let i = engine.template().filters.iter().position(|f| f.id == id).unwrap_or_else(|| panic!("filtre {id}"));
    stats.filter_hits[i]
}

fn rule_hits(engine: &Engine, stats: &Stats, id: &str) -> u64 {
    let i = engine.template().rules.iter().position(|r| r.id == id).unwrap_or_else(|| panic!("règle {id}"));
    stats.rule_hits[i]
}

const SYSLOG: &str = "2026-11-09T00:00:06+00:00 a.etam-sb.kbrw.fr haproxy[227]: ";

/// Ligne HTTP : client, frontend, `backend/server`, statut, requête.
fn http(client: &str, frontend: &str, backend: &str, status: u16, req: &str) -> String {
    format!(
        "a.etam-sb.kbrw.fr  {SYSLOG}{client} [09/Nov/2026:00:00:06.788] {frontend} {backend} tls[-/-/0] t[0/0/0/1/1] c[{status}] sz[174] - - ---- 1/1/0/0/0 0/0 hds[{{}}] req[\"{req}\"]\n"
    )
}

const V6: &str = "2001:41d0:9a:a10:b00:6100:0:1:56473";
const FRONT: &str = "node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80";
const BACK: &str = "etam_sb_user-local_ipv6-8080/etam-user01";

#[test]
fn route_filters_and_route_rules_read_the_haproxy_request() {
    let body = "format='haproxy_syslog'\n[format.options]\ncompact_header=true\n\
[[filters]]\nid='ping'\naction='drop_entry'\nroutes=['GET /api/ping']\n\
[[rules]]\nid='admin'\nroute='/api/etam_admin/{v}'\nstrategy='pseudonymize'\ntoken='ADMIN'\n\
[[rules]]\nid='riak'\nroute='/riak/{bucket}/{key}'\ntargets=['key']\nstrategy='pseudonymize'\ntoken='RIAKKEY'\n\
[allowlist]\ncidrs=['2001:41d0:9a::/48']\n";
    let e = engine(body);
    let input = [
        http(V6, FRONT, BACK, 200, "GET /api/ping HTTP/1.1"),
        http(V6, FRONT, BACK, 200, "POST /api/ping HTTP/1.1"),
        http(V6, FRONT, BACK, 200, "GET //api/etam_admin/jean.dupont@example.com HTTP/1.1"),
        http(V6, FRONT, BACK, 200, "GET //riak/etam_sb_orders/900449662?returnbody=true HTTP/1.1"),
        http(V6, FRONT, BACK, 200, "GET /api/etam_admin/jean.dupont@example.com/login HTTP/1.1"),
    ]
    .concat();
    let (out, stats) = anonymize(&e, &input);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(filter_hits(&e, &stats, "t/x:ping"), 1);
    assert!(lines[0].ends_with("req[\"POST /api/ping HTTP/1.1\"]"), "{out}");
    // Le segment nommé est remplacé jusqu'au protocole, pas au-delà.
    assert!(lines[1].contains("req[\"GET //api/etam_admin/ADMIN_") && lines[1].ends_with(" HTTP/1.1\"]"), "{out}");
    assert!(lines[2].contains("req[\"GET //riak/etam_sb_orders/RIAKKEY_") && lines[2].ends_with("?returnbody=true HTTP/1.1\"]"), "{out}");
    // Route exacte : `/login` en plus ne correspond pas ; l'email est pris par le filet.
    assert!(lines[3].contains("/api/etam_admin/EMAIL_") && lines[3].ends_with("/login HTTP/1.1\"]"), "{out}");
    assert_eq!(rule_hits(&e, &stats, "t/x:admin"), 1);
    assert_eq!(rule_hits(&e, &stats, "t/x:riak"), 1);
    assert!(!out.contains("jean.dupont") && !out.contains("900449662"), "{out}");
    // compact_header : ni date ISO, ni pid ; le host n'apparaît qu'une fois.
    assert!(lines.iter().all(|l| l.starts_with("a.etam-sb.kbrw.fr  2001:41d0:9a:a10:b00:6100:0:1:56473 [09/Nov/2026")), "{out}");
    assert!(!out.contains("haproxy[227]") && !out.contains("2026-11-09T"), "{out}");
}

#[test]
fn without_compact_header_the_syslog_header_is_kept() {
    let e = engine("format='haproxy_syslog'\nextends=['kbrw/common@^1']\n[[filters]]\nid='ping'\nroutes=['/api/ping']\n");
    let input = [http("198.51.100.65:40461", FRONT, BACK, 200, "GET /api/ping HTTP/1.1"), http("198.51.100.65:40461", FRONT, BACK, 200, "GET /api/orders?session_id=abcd1234 HTTP/1.1")].concat();
    let (out, stats) = anonymize(&e, &input);
    assert_eq!(stats.dropped, 1);
    assert!(out.starts_with(&format!("a.etam-sb.kbrw.fr  {SYSLOG}IP_")), "{out}");
    // Sans liste `[extractors]`, l'extracteur du format et `http_request` sont actifs.
    assert!(out.contains(":40461 [09/Nov/2026:00:00:06.788] node-local_ipv6-"), "{out}");
    assert!(out.ends_with("req[\"GET /api/orders?session_id=[CREDENTIALS] HTTP/1.1\"]\n"), "{out}");
    assert_eq!(rule_hits(&e, &stats, "kbrw/common:credential-keys"), 1);
}

#[test]
fn where_conditions_are_anded_with_each_other_and_with_the_other_conditions() {
    let body = "format='haproxy_syslog'\n[format.options]\ncompact_header=true\n\
[[filters]]\nid='bad'\nwhere={ request=['<BADREQ>'], server=['<NOSRV>'] }\n\
[[filters]]\nid='refused-env'\nwhere={ status=[400, 404, '403'] }\nroutes=['/.env']\n\
[[filters]]\nid='tls-front'\nkinds=['tls_error']\nwhere={ frontend=['front-a', 'front-b'] }\n\
[[filters]]\nid='sftp-timeouts'\nheader='sftp-frontend'\nwhere={ termination=['sD'] }\n";
    let e = engine(body);
    let h = "a.etam-sb.kbrw.fr  ";
    let tls = |front: &str| format!("{h}{SYSLOG}{V6} [09/Nov/2026:00:06:56.849] {front}/1: SSL handshake failure\n");
    let tcp = |state: &str| format!("{h}{SYSLOG}{V6} [09/Nov/2026:00:00:32.160] sftp-frontend-ipv4 sftp-backend-ipv6/primary 1/0/60679 6972 {state} 1/1/0/0/0 0/0\n");
    let input = [
        // bad : les deux champs sont requis.
        http(V6, FRONT, "back/<NOSRV>", 400, "<BADREQ>"),
        http(V6, FRONT, "back/srv-kept-1", 400, "<BADREQ>"),
        http(V6, FRONT, "back/<NOSRV>", 503, "GET /kept-2 HTTP/1.1"),
        // refused-env : statut ET route ; entier ou chaîne, même comparaison.
        http(V6, FRONT, BACK, 404, "GET /.env HTTP/1.1"),
        http(V6, FRONT, BACK, 403, "GET /.env HTTP/1.1"),
        http(V6, FRONT, BACK, 200, "GET /.env?kept-3 HTTP/1.1"),
        http(V6, FRONT, BACK, 404, "GET /kept-4 HTTP/1.1"),
        http(V6, FRONT, BACK, 4040, "GET /.env?kept-5 HTTP/1.1"),
        // tls-front : type d'entrée ET champ.
        tls("front-a"),
        tls("front-b"),
        tls("front-kept-6"),
        http(V6, "front-a", BACK, 200, "GET /kept-7 HTTP/1.1"),
        // sftp-timeouts : regex d'en-tête ET champ.
        tcp("sD"),
        tcp("kept-8"),
    ]
    .concat();
    let (out, stats) = anonymize(&e, &input);
    assert_eq!(filter_hits(&e, &stats, "t/x:bad"), 1, "{out}");
    assert_eq!(filter_hits(&e, &stats, "t/x:refused-env"), 2, "{out}");
    assert_eq!(filter_hits(&e, &stats, "t/x:tls-front"), 2, "{out}");
    assert_eq!(filter_hits(&e, &stats, "t/x:sftp-timeouts"), 1, "{out}");
    assert_eq!(out.lines().count(), 8, "{out}");
    for i in 1..=8 {
        assert!(out.contains(&format!("kept-{i}")), "kept-{i} manque dans :\n{out}");
    }
}

#[test]
fn entry_kinds_are_reported_and_unexpected_lines_still_go_through_the_detectors() {
    let lib = Library::builtin();
    let e = Engine::new(Arc::new(lib.compile("kbrw/haproxy").unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap();
    let h = "a.etam-sb.kbrw.fr  ";
    let input = [
        http("198.51.100.65:40461", "node-public_ipv4-51_75_10_28-443~", BACK, 200, "GET /api/orders HTTP/1.1"),
        format!("{h}{SYSLOG}198.51.100.178:60268 [09/Nov/2026:00:00:32.160] sftp-frontend-ipv4 sftp-backend-ipv6/primary 1/0/60679 6972 sD 1/1/0/0/0 0/0\n"),
        format!("{h}{SYSLOG}198.51.100.153:46054 [09/Nov/2026:00:06:56.849] node-public_ipv4-188_165_78_170-443/1: Timeout during SSL handshake\n"),
        // Messages d'administration, ligne coupée, ligne sans en-tête, octets quelconques.
        format!("{h}{SYSLOG}Server etam_sb_admin-local_ipv6-8080/etam-admin01 is DOWN, alert sent to jean.dupont@example.com from 203.0.113.10\n"),
        format!("{h}{SYSLOG}198.51.100.66:40462 [09/Nov/2026:00:00:07.100] node-public_ipv4-51_75_10_28-443~ back/srv tls[TLSv1.3/TLS_AES_256_GCM_SHA384/28] t[0/0\n"),
        "no header at all, token=abcd1234efgh from 198.51.100.67\n".to_string(),
        format!("{h}{SYSLOG}\u{0}\u{1}:: [ ] / ~ hds[ req[\"\n"),
        format!("{h}\r\n"),
    ]
    .concat();
    let (entries, _) = sandbox(&e, input.as_bytes(), 100);
    let kinds: Vec<&str> = entries.iter().map(|x| x.kind.as_str()).collect();
    assert_eq!(kinds, vec!["http", "tcp", "tls_error", "other", "other", "other", "other"]);
    let (out, stats) = anonymize(&e, &input);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 7, "{out}");
    assert!(lines[3].contains("etam-admin01 is DOWN, alert sent to EMAIL_e3236363 from IP_"), "{out}");
    // La ligne coupée garde les champs lus avant la coupure : client et frontend sont pris par leurs règles.
    assert!(lines[4].contains(":40462 [09/Nov/2026:00:00:07.100] node-public_ipv4-IP_") && lines[4].ends_with("t[0/0"), "{out}");
    assert!(lines[5].starts_with("no header at all, token=[CREDENTIALS] from IP_"), "{out}");
    for leaked in ["198.51.100.", "203.0.113.10", "51_75_10_28", "188_165_78_170", "jean.dupont", "abcd1234efgh", "\r"] {
        assert!(!out.contains(leaked), "« {leaked} » dans :\n{out}");
    }
    assert_eq!(stats.entries_in, 7);
    assert_eq!(stats.safety_total(), 0, "{:?}", stats.findings);
}

#[test]
fn extractors_run_only_when_the_template_enables_them() {
    let rules = "[[rules]]\nid='code'\nkeys=['url.query.code']\nstrategy='redact'\nlabel='CODE'\n\
[[rules]]\nid='port'\nkeys=['haproxy.client_port']\nstrategy='redact'\nlabel='PORT'\n\
[[rules]]\nid='hds'\nkeys=['haproxy.hds.*']\nstrategy='redact'\nlabel='HEADER'\n\
[[rules]]\nid='cookie'\nkeys=['haproxy.req_cookie']\nstrategy='redact'\nlabel='COOKIE'\n";
    let line = format!(
        "a.etam-sb.kbrw.fr  {SYSLOG}{V6} [09/Nov/2026:00:00:06.788] {FRONT} {BACK} tls[-/-/0] t[0/0/0/1/1] c[200] sz[174] sid=s3ss10n - ---- 1/1/0/0/0 0/0 hds[{{shop.kbrw.fr|curl/8.5.0}}] req[\"GET /cb?code=xyz&state=abc HTTP/1.1\"]\n"
    );
    let with = |enabled: &str| anonymize(&engine(&format!("format='haproxy_syslog'\n[format.options]\ncompact_header=true\n[extractors]\nenabled=[{enabled}]\n{rules}[allowlist]\ncidrs=['2001:41d0:9a::/48']\n")), &line).0;

    let both = with("'haproxy', 'http_request'");
    assert!(both.contains(":[PORT] [09/Nov") && both.contains("sz[174] [COOKIE] - ----") && both.contains("hds[{[HEADER]|[HEADER]}]") && both.contains("/cb?code=[CODE]&state=abc HTTP/1.1"), "{both}");
    let haproxy_only = with("'haproxy'");
    assert!(haproxy_only.contains(":[PORT] [09/Nov") && haproxy_only.contains("/cb?code=xyz&state=abc"), "{haproxy_only}");
    let request_only = with("'http_request'");
    assert!(request_only.contains(":56473 [09/Nov") && request_only.contains("sid=s3ss10n") && request_only.contains("/cb?code=[CODE]&state=abc"), "{request_only}");
    let none = with("");
    assert_eq!(none, line.replace(SYSLOG, ""));
}

#[test]
fn query_string_credentials_are_masked_in_elixir_headers_too() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let input = "j.kbrw.fr  09:39:05.203 [info]  in GET /auth/callback?SAMLResponse=PHNhbWxwOlJlc3BvbnNl%3D%3D&state=abc\n\
j.kbrw.fr  09:39:05.229 [info]  Sent 302 in 26ms\tGET /auth/callback?SAMLResponse=PHNhbWxwOlJlc3BvbnNl%3D%3D&state=abc\n\
j.kbrw.fr  09:39:06.000 [info] GET //api/x?Session_Id=0123abcd&page=2\n";
    let (out, stats) = anonymize(&e, input);
    assert_eq!(out.matches("/auth/callback?SAMLResponse=[CREDENTIALS]&state=abc").count(), 2, "{out}");
    assert!(out.contains("GET //api/x?Session_Id=[CREDENTIALS]&page=2"), "{out}");
    assert_eq!(rule_hits(&e, &stats, "kbrw/common:credential-keys"), 3);
    assert_eq!(stats.safety_total(), 0);
}

#[test]
fn riak_console_groups_multiline_entries_per_host_and_reads_riak_keys() {
    let input = "riakn04.etam-sb.kbrw.fr  2026-11-09 14:25:54.020 [error] <0.1166.0>@riak_kv_vnode:handle_command:912 CRASH REPORT Process <0.1166.0> crashed on <<\"etam_sb_etam_admin\">>/<<\"jean.dupont@example.com\">>\r\n\
riakn07.etam-sb.kbrw.fr  2026-11-09 14:25:54.021 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object <<\"etam_sb_order_audits\">>/<<\"900424011\">> (5652713 bytes)\r\n\
riakn04.etam-sb.kbrw.fr      {badmatch,{error,{<<\"etam_sb_carts\">>/<<\"cart-42\">>,timeout}}}\r\n\
riakn07.etam-sb.kbrw.fr  2026-11-09 14:25:54.022 [info] <0.24584.4878> Merged {[\"/var/lib/riak/bitcask/1/2.bitcask.data\"],[]} in 0.11353 seconds.\r\n\
riakn04.etam-sb.kbrw.fr      [{riak_kv_vnode,do_get_object,3,[{file,\"src/riak_kv_vnode.erl\"},{line,1837}]}]\r\n";

    // Template de base : seule la clé qui est un email est remplacée.
    let e = engine("format='lager_syslog'\nextends=['kbrw/riak-console@^1']\n");
    let (out, stats) = anonymize(&e, input);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(stats.entries_in, 3);
    assert_eq!(lines.len(), 5, "{out}");
    // L'entrée multiligne de riakn04 est regroupée, à la place de sa première ligne.
    assert!(lines[0].starts_with("riakn04.etam-sb.kbrw.fr  2026-11-09 14:25:54.020 [error] <0.1166.0>@riak_kv_vnode:handle_command:912 CRASH REPORT"), "{out}");
    assert!(lines[0].ends_with("<<\"etam_sb_etam_admin\">>/<<\"EMAIL_e3236363\">>"), "{out}");
    assert_eq!(lines[1], "      {badmatch,{error,{<<\"etam_sb_carts\">>/<<\"cart-42\">>,timeout}}}");
    assert_eq!(lines[2], "      [{riak_kv_vnode,do_get_object,3,[{file,\"src/riak_kv_vnode.erl\"},{line,1837}]}]");
    assert_eq!(
        lines[3],
        "riakn07.etam-sb.kbrw.fr  2026-11-09 14:25:54.021 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object <<\"etam_sb_order_audits\">>/<<\"900424011\">> (5652713 bytes)"
    );
    assert!(lines[4].ends_with("in 0.11353 seconds."), "{out}");
    assert!(!out.contains("jean.dupont") && !out.contains('\r'), "{out}");
    assert_eq!(stats.safety_total(), 0, "{:?}", stats.findings);

    // Règle `riak-keys` activée : toutes les clés sont remplacées, les buckets restent.
    let e = engine("format='lager_syslog'\nextends=['kbrw/riak-console@^1']\n[[rules]]\nid='kbrw/riak-console:riak-keys'\nenabled=true\n");
    let (out, stats) = anonymize(&e, input);
    assert_eq!(out.matches(">>/<<\"RIAKKEY_").count(), 3, "{out}");
    assert_eq!(rule_hits(&e, &stats, "kbrw/riak-console:riak-keys"), 3);
    for kept in ["<<\"etam_sb_etam_admin\">>/", "<<\"etam_sb_order_audits\">>/", "<<\"etam_sb_carts\">>/"] {
        assert!(out.contains(kept), "{out}");
    }
    for leaked in ["jean.dupont", "900424011", "cart-42", "\r"] {
        assert!(!out.contains(leaked), "« {leaked} » dans :\n{out}");
    }
    assert_eq!(stats.safety_total(), 0, "{:?}", stats.findings);
}

#[test]
fn riak_console_dedup_ignores_the_lager_timestamp_and_pid() {
    let e = engine("format='lager_syslog'\nextends=['kbrw/riak-console@^1']\n[[filters]]\nid='kbrw/riak-console:dedup'\nenabled=true\n");
    let input = "r.kbrw.fr  2026-11-09 00:01:05.050 [info] <0.24584.4878> Compaction skipped for partition 12\n\
r.kbrw.fr  2026-11-09 00:01:06.051 [info] <0.24585.4878> Compaction skipped for partition 12\n\
r.kbrw.fr  2026-11-10 00:01:07.052 [info] <0.9.0> Compaction skipped for partition 12\n\
r.kbrw.fr  2026-11-10 00:01:08.000 [info] <0.9.0> Compaction skipped for partition 13\n";
    let (out, stats) = anonymize(&e, input);
    assert_eq!(
        out,
        "r.kbrw.fr  2026-11-09 00:01:05.050 [info] <0.24584.4878> Compaction skipped for partition 12\n\
r.kbrw.fr  ↳ entrée précédente répétée 2 fois, la dernière à 00:01:07.052\n\
r.kbrw.fr  2026-11-10 00:01:08.000 [info] <0.9.0> Compaction skipped for partition 13\n"
    );
    assert_eq!(stats.deduplicated, 2);
}

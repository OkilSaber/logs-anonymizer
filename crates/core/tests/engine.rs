//! Moteur de bout en bout : règles, filet de sécurité, bac à sable, pipeline.

// Ces tests s'appuient sur les templates et le corpus, qui ne font pas partie du dépôt.
#![cfg(logano_templates)]

use flate2::write::GzEncoder;
use flate2::Compression;
use logano_core::engine::SafetyAction;
use logano_core::pipeline::{open_input, open_input_counted, run, sandbox, Layout, RunOptions};
use logano_core::template::testing::TEST_KEY;
use logano_core::{CoreError, Engine, EngineOptions, Library, Stats};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const HEAD: &str = "[template]\nid='t/x'\nname='x'\nversion='1.0.0'\nschema_version=1\n";

fn engine_with(body: &str, opts: EngineOptions) -> Engine {
    let mut lib = Library::builtin();
    lib.add_str(&format!("{HEAD}{body}")).unwrap();
    Engine::new(Arc::new(lib.compile("t/x").unwrap()), opts).unwrap()
}

fn engine(body: &str) -> Engine {
    engine_with(body, EngineOptions::with_key(TEST_KEY))
}

fn anonymize(engine: &Engine, input: &str) -> (String, Stats) {
    let mut out = Vec::new();
    let stats = run(input.as_bytes(), engine, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    (String::from_utf8(out).unwrap(), stats)
}

#[test]
fn safety_net_replaces_what_no_rule_covers_and_reports_it() {
    // Template sans aucune règle : tout repose sur le filet.
    let e = engine("format='plain'\n");
    let (out, stats) = anonymize(&e, "owner jean.dupont@example.com from 198.51.100.65 with Basic dXNlcjpwYXNzd29yZA==\nnothing here\n");
    assert!(out.starts_with("owner EMAIL_"), "{out}");
    assert!(out.contains(" from IP_") && out.contains("Basic [CREDENTIALS]") && out.contains("nothing here\n"), "{out}");
    for leaked in ["jean.dupont", "198.51.100.65", "dXNlcjpw"] {
        assert!(!out.contains(leaked), "{out}");
    }
    assert_eq!(stats.safety_total(), 3);
    assert_eq!(stats.findings.len(), 3);
    assert!(stats.findings.iter().all(|f| f.replaced && f.line_no == 1 && !f.context.contains("jean.dupont")));
    assert_eq!(stats.modified, 1);
}

#[test]
fn report_mode_leaves_the_value_and_gives_no_context() {
    let mut opts = EngineOptions::with_key(TEST_KEY);
    opts.safety = SafetyAction::Report;
    let e = engine_with("format='plain'\n", opts);
    let (out, stats) = anonymize(&e, "owner jean.dupont@example.com\n");
    assert_eq!(out, "owner jean.dupont@example.com\n");
    assert_eq!(stats.safety_total(), 1);
    assert_eq!(stats.findings[0].context, "");
    assert!(!stats.findings[0].replaced);
}

#[test]
fn a_disabled_inherited_rule_is_caught_by_the_safety_net() {
    let e = engine("format='plain'\nextends=['kbrw/common@^1']\n[[rules]]\nid='kbrw/common:emails'\nenabled=false\n");
    let (out, stats) = anonymize(&e, "owner jean.dupont@example.com\n");
    assert!(out.starts_with("owner EMAIL_") && !out.contains("jean.dupont"), "{out}");
    assert_eq!(stats.safety_total(), 1);
}

#[test]
fn keep_protects_from_weak_detectors_but_never_from_certain_classes() {
    let body = "format='elixir_syslog'\nextends=['kbrw/common@^1']\n[[rules]]\nid='ids'\nkeys=['ref']\nstrategy='keep'\npriority=400\n";
    let e = engine(body);
    let (out, stats) = anonymize(&e, "h.kbrw.fr  10:00:00.000 [info]  x\nh.kbrw.fr  {\"ref\": \"0612345678\", \"other\": \"0612345678\"}\n");
    assert!(out.contains("\"ref\": \"0612345678\""), "{out}");
    assert!(out.contains("\"other\": \"PHONE_"), "{out}");
    assert_eq!(stats.safety_total(), 0);
    // Un email sous une clé gardée : la règle est masquée par `keep`, le filet le rattrape.
    let (out, stats) = anonymize(&e, "h.kbrw.fr  10:00:00.000 [info]  x\nh.kbrw.fr  {\"ref\": \"jean.dupont@example.com\"}\n");
    assert!(out.contains("\"ref\": \"EMAIL_") && !out.contains("jean.dupont"), "{out}");
    assert_eq!(stats.safety_total(), 1);
}

#[test]
fn allowlists_apply_to_rules_and_to_the_safety_net() {
    let body = "format='plain'\nextends=['kbrw/common@^1']\n[allowlist]\nemails=['*+mailer@kbrw.fr']\ncidrs=['198.51.100.0/24']\nvalues=['hackney/*']\n";
    let (out, stats) = anonymize(&engine(body), "from jardiland+mailer@kbrw.fr to jean.dupont@kbrw.fr via 198.51.100.65 and 203.0.113.10\n");
    assert!(out.contains("from jardiland+mailer@kbrw.fr to EMAIL_"), "{out}");
    assert!(out.contains("via 198.51.100.65 and IP_"), "{out}");
    assert!(!out.contains("jean.dupont") && !out.contains("203.0.113.10"), "{out}");
    assert_eq!(stats.safety_total(), 0);
}

#[test]
fn route_and_regex_rules_replace_only_their_target() {
    let body = "format='elixir_syslog'\n[[rules]]\nid='psa-user'\nroutes=['/api/user/{v}', '/api/{v}/orders/**']\nstrategy='pseudonymize'\ntoken='PSAUSER'\n\
[[rules]]\nid='garage'\nregex='custom_garage_id:(?P<v>[0-9A-Z]+)'\nstrategy='pseudonymize'\ntoken='GARAGE'\n\
[[rules]]\nid='user-id'\nkeys=['user_id']\nstrategy='pseudonymize'\ntoken='PSAUSER'\n";
    let input = "p.kbrw.fr  06:49:31.793 [info] GET //api/user/M0000001\n\
p.kbrw.fr  06:49:31.800 [info] GET /api/M0000001/orders/12/lines\n\
p.kbrw.fr  06:49:31.966 [debug] [services@2001:41d0:9a:a12::2][Elixir.Api.Filters][#PID<0.30774.4>] %{\"route\" => \"root\", \"user_id\" => \"M0000001\"}\n\
p.kbrw.fr  06:50:50.270 [info] Query : custom_user_status:to_print%20AND%20custom_garage_id:000000E\n";
    let (out, stats) = anonymize(&engine(body), input);
    let token = out.split("/api/user/").nth(1).unwrap().lines().next().unwrap().to_string();
    assert!(token.starts_with("PSAUSER_"), "{out}");
    assert!(out.contains(&format!("GET /api/{token}/orders/12/lines")), "{out}");
    assert!(out.contains(&format!("\"user_id\" => \"{token}\"")), "{out}");
    assert!(out.contains("custom_garage_id:GARAGE_") && out.contains("custom_user_status:to_print%20AND"), "{out}");
    assert!(!out.contains("M0000001") && !out.contains("000000E"), "{out}");
    assert_eq!(stats.rule_hits.iter().sum::<u64>(), 4);
}

#[test]
fn a_value_designated_by_a_key_is_replaced_whole_even_around_an_inner_credential() {
    // `token=…` (détecteur, priorité 290) est dans une valeur que la règle par clé (200)
    // masque en entier : l'URL ne doit pas rester en clair autour du jeton.
    let body = "format='elixir_syslog'\nextends=['kbrw/common@^1']\n[[rules]]\nid='links'\nkeys=['urlbill']\nstrategy='redact'\nlabel='LINK'\n";
    let (out, stats) = anonymize(&engine(body), "h.kbrw.fr  10:00:00.000 [info]  x %{urlbill: \"https://bills.example.com/b/778899?token=abcdef123456&lang=fr\", other: \"token=zzzz9999\"}\n");
    assert!(out.contains("urlbill: \"[LINK]\""), "{out}");
    assert!(out.contains("other: \"token=[CREDENTIALS]\""), "{out}");
    assert!(!out.contains("bills.example.com") && !out.contains("778899") && !out.contains("abcdef123456"), "{out}");
    assert_eq!(stats.safety_total(), 0);
}

#[test]
fn drop_field_removes_key_and_value_and_drop_entry_removes_the_entry() {
    let body = "format='elixir_syslog'\n[[rules]]\nid='nopayload'\nkeys=['payload']\nstrategy='drop_field'\n[[rules]]\nid='secret-entries'\nkeys=['top_secret']\nstrategy='drop_entry'\n";
    let input = "h.kbrw.fr  10:00:00.000 [info]  a\nh.kbrw.fr  {\"id\": 1, \"payload\": \"abc\", \"z\": 2}\nh.kbrw.fr  10:00:01.000 [info]  b %{top_secret: \"x\"}\nh.kbrw.fr  10:00:02.000 [info]  c\n";
    let (out, stats) = anonymize(&engine(body), input);
    assert_eq!(out, "h.kbrw.fr  10:00:00.000 [info]  a\n  {\"id\": 1, \"z\": 2}\nh.kbrw.fr  10:00:02.000 [info]  c\n");
    assert_eq!((stats.entries_in, stats.entries_out, stats.dropped), (3, 2, 1));
}

#[test]
fn numbers_and_atoms_are_quoted_when_replaced() {
    let body = "format='elixir_syslog'\n[[rules]]\nid='zip'\nkeys=['zipcode']\nstrategy='mask_partial'\nmask='keep_prefix:2'\n";
    let (out, _) = anonymize(&engine(body), "h.kbrw.fr  10:00:00.000 [info]  a\nh.kbrw.fr  {\"zipcode\": 75000, \"n\": 1} %{zipcode: 69001, s: \"69002\"}\n");
    assert!(out.contains("{\"zipcode\": \"75***\", \"n\": 1} %{zipcode: \"69***\", s: \"69002\"}"), "{out}");
}

#[test]
fn consecutive_identical_entries_of_a_source_collapse_into_a_counter() {
    let body = "format='elixir_syslog'\n[[filters]]\nid='dd'\naction='dedup'\nignore=['timestamp','pid','reference']\n";
    let mut input = String::new();
    // Trois fois la même erreur avec sa pile d'appels sur a, entrelacée avec b ; seuls
    // l'heure, le PID et la référence changent.
    for i in 0..3 {
        input.push_str(&format!("a.kbrw.fr  10:00:0{i}.000 [error] Task #PID<0.{i}.0> failed\na.kbrw.fr  ** (ArgumentError) argument error\na.kbrw.fr  \t#Reference<0.1.2.{i}>\n"));
        input.push_str(&format!("b.kbrw.fr  10:00:0{i}.500 [info]  tick {i}\n"));
    }
    input.push_str("a.kbrw.fr  10:00:09.000 [info]  recovered\n");
    for _ in 0..2 {
        input.push_str("b.kbrw.fr  10:00:10.000 [info]  same again\n");
    }
    let (out, stats) = anonymize(&engine(body), &input);
    let expected = "a.kbrw.fr  10:00:00.000 [error] Task #PID<0.0.0> failed\n  ** (ArgumentError) argument error\n  \t#Reference<0.1.2.0>\n\
b.kbrw.fr  10:00:00.500 [info]  tick 0\nb.kbrw.fr  10:00:01.500 [info]  tick 1\nb.kbrw.fr  10:00:02.500 [info]  tick 2\n\
a.kbrw.fr  ↳ entrée précédente répétée 2 fois, la dernière à 10:00:02.000\na.kbrw.fr  10:00:09.000 [info]  recovered\n\
b.kbrw.fr  10:00:10.000 [info]  same again\nb.kbrw.fr  ↳ entrée précédente répétée 1 fois, la dernière à 10:00:10.000\n";
    assert_eq!(out, expected);
    assert_eq!((stats.entries_in, stats.entries_out, stats.deduplicated), (9, 6, 3));
    // Sans le filtre, rien n'est fusionné.
    let (out, stats) = anonymize(&engine("format='elixir_syslog'\n"), &input);
    assert_eq!((out.lines().count(), stats.deduplicated), (15, 0));
}

#[test]
fn faithful_layout_repeats_the_host_on_every_line() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let input = "a.kbrw.fr  10:00:00.000 [info]  one\nb.kbrw.fr  10:00:00.001 [info]  two\na.kbrw.fr  \tcookie : s=jean@example.com%7Cx\n";
    let mut out = Vec::new();
    let opts = RunOptions { layout: Layout::Faithful, ..Default::default() };
    run(input.as_bytes(), &e, &mut out, &opts, &AtomicBool::new(false), &mut |_| {}).unwrap();
    let out = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "a.kbrw.fr  10:00:00.000 [info]  one");
    assert!(lines[1].starts_with("a.kbrw.fr  \tcookie : s=EMAIL_"), "{out}");
    assert_eq!(lines[2], "b.kbrw.fr  10:00:00.001 [info]  two");
}

#[test]
fn sandbox_segments_rebuild_both_sides_and_name_the_rule() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let input = "h.kbrw.fr  09:39:05.203 [info]  in GET /api/x\nh.kbrw.fr  \tcookie : etam_admin-auth=jean.dupont@example.com%7C1794217138%7CAbCdEfGhIjKlMnOpQrStUvWxYz0=\nh.kbrw.fr  \tauthorization : Basic dXNlcjpwYXNzd29yZA==\nh.kbrw.fr  10:00:00.000 [info]  in GET /api/ping\n";
    let (entries, _) = sandbox(&e, input.as_bytes(), 100);
    assert_eq!(entries.len(), 2);
    let first = &entries[0];
    let raw: String = first.raw.iter().map(|s| s.text.as_str()).collect();
    let out: String = first.out.iter().map(|s| s.text.as_str()).collect();
    assert!(raw.contains("jean.dupont@example.com%7C1794217138") && raw.contains("Basic dXNlcjpwYXNzd29yZA=="));
    assert!(out.contains("etam_admin-auth=EMAIL_") && out.contains("[SESSION]") && out.contains("Basic [CREDENTIALS]"));
    let pairs = |segs: &[logano_core::Segment]| segs.iter().filter_map(|s| s.rule.clone().map(|r| (r, s.text.clone()))).collect::<Vec<_>>();
    let raw_marked = pairs(&first.raw);
    assert_eq!(raw_marked[0], ("kbrw/common:emails".to_string(), "jean.dupont@example.com".to_string()));
    assert_eq!(raw_marked[1].0, "kbrw/common:cookies");
    assert_eq!(raw_marked[2], ("kbrw/common:auth-headers".to_string(), "Basic dXNlcjpwYXNzd29yZA==".to_string()));
    let out_marked = pairs(&first.out);
    assert!(out_marked[0].1.starts_with("EMAIL_"));
    assert_eq!(out_marked[1].1, "[SESSION]");
    assert_eq!(out_marked[2].1, "Basic [CREDENTIALS]");
    assert_eq!(entries[1].dropped_by.as_deref(), Some("kbrw/elixir:ping"));
    assert!(entries[1].out.is_empty());
}

#[test]
fn sandbox_marks_safety_net_edits_at_the_right_place() {
    let e = engine("format='plain'\n[[rules]]\nid='tok'\nregex='tok=(?P<v>\\w+)'\nstrategy='redact'\nlabel='T'\n");
    let (entries, _) = sandbox(&e, b"tok=abc mail jean@example.com tok=defgh end", 10);
    let raw: Vec<_> = entries[0].raw.iter().map(|s| (s.text.as_str(), s.safety)).collect();
    assert_eq!(raw, vec![("tok=", false), ("abc", false), (" mail ", false), ("jean@example.com", true), (" tok=", false), ("defgh", false), (" end", false)]);
    let out: String = entries[0].out.iter().map(|s| s.text.as_str()).collect();
    assert!(out.starts_with("tok=[T] mail EMAIL_") && out.ends_with(" tok=[T] end"), "{out}");
    let safety_out: Vec<_> = entries[0].out.iter().filter(|s| s.safety).map(|s| s.text.clone()).collect();
    assert_eq!(safety_out.len(), 1);
    assert!(safety_out[0].starts_with("EMAIL_"));
}

fn big_input(entries: usize) -> String {
    let mut s = String::new();
    for i in 0..entries {
        let host = format!("etam-services0{}.etam-sb.kbrw.fr", i % 3 + 1);
        s.push_str(&format!("{host}  10:{:02}:{:02}.{:03} [info]  in GET /api/order/{i}\n", i / 3600 % 60, i / 60 % 60, i % 1000));
        s.push_str(&format!("{host}  \tcookie : etam_admin-auth=user{}@example.com%7C1794217138%7CAbCdEfGhIjKlMnOpQrStUvWxYz0=\n", i % 500));
        s.push_str(&format!("{host}  \n"));
    }
    s
}

#[test]
fn many_batches_keep_the_order_and_tokens_stay_consistent() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let input = big_input(30_000);
    let mut out = Vec::new();
    let mut ticks = 0;
    // Petits lots pour forcer beaucoup de parallélisme et de réassemblage.
    let opts = RunOptions { batch_bytes: 16 << 10, ..Default::default() };
    let stats = run(input.as_bytes(), &e, &mut out, &opts, &AtomicBool::new(false), &mut |_| ticks += 1).unwrap();
    assert_eq!((stats.entries_in, stats.entries_out), (30_000, 30_000));
    assert!(ticks > 1);
    let out = String::from_utf8(out).unwrap();
    assert!(!out.contains("@example.com") && !out.contains("AbCdEf"));
    let mut tokens = std::collections::HashMap::new();
    let mut n = 0;
    for (i, pair) in out.lines().collect::<Vec<_>>().chunks(2).enumerate() {
        assert!(pair[0].ends_with(&format!("/api/order/{i}")), "ordre rompu à l'entrée {i} : {}", pair[0]);
        let token = pair[1].split("auth=").nth(1).unwrap().split('[').next().unwrap();
        assert_eq!(tokens.entry(i % 500).or_insert_with(|| token.to_string()).as_str(), token);
        n += 1;
    }
    assert_eq!(n, 30_000);
    assert_eq!(tokens.values().collect::<std::collections::HashSet<_>>().len(), 500);
}

#[test]
fn gzip_input_including_concatenated_members_and_truncation() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let dir = std::env::temp_dir().join(format!("logano-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let gz = |data: &[u8]| {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    };
    let input = big_input(2_000);
    let (first, second) = input.split_at(input.len() / 2 + 7);
    // Deux membres gzip concaténés, coupés au milieu d'une ligne.
    let mut bytes = gz(first.as_bytes());
    bytes.extend(gz(second.as_bytes()));
    let path = dir.join("erlang.log.gz");
    std::fs::write(&path, &bytes).unwrap();
    let mut out = Vec::new();
    let stats = run(open_input(&path).unwrap(), &e, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    assert_eq!(stats.entries_out, 2_000);
    assert!(stats.input_error.is_none());
    let (plain, _) = anonymize(&e, &input);
    assert_eq!(String::from_utf8(out).unwrap(), plain);

    // L'avancement se lit en octets compressés : à la fin, tout le fichier a été lu.
    let input_file = open_input_counted(&path).unwrap();
    assert_eq!(input_file.size, bytes.len() as u64);
    let (read, mut seen) = (input_file.read.clone(), Vec::new());
    let mut sink = Vec::new();
    let opts = RunOptions { batch_bytes: 32 << 10, ..Default::default() };
    run(input_file.reader, &e, &mut sink, &opts, &AtomicBool::new(false), &mut |_| seen.push(read.load(Ordering::Relaxed))).unwrap();
    assert_eq!(read.load(Ordering::Relaxed), bytes.len() as u64);
    assert!(seen.windows(2).all(|w| w[0] <= w[1]) && seen.iter().all(|n| *n <= bytes.len() as u64));

    // Fichier tronqué : ce qui est lisible est traité, l'erreur est signalée.
    std::fs::write(&path, &bytes[..bytes.len() / 3]).unwrap();
    let mut out = Vec::new();
    let stats = run(open_input(&path).unwrap(), &e, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    assert!(stats.input_error.is_some());
    assert!(stats.entries_out > 100 && stats.entries_out < 2_000, "{}", stats.entries_out);

    // Fichier non compressé.
    let path = dir.join("erlang.log");
    std::fs::write(&path, &input).unwrap();
    let mut out = Vec::new();
    run(open_input(&path).unwrap(), &e, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), plain);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn cancellation_stops_the_run() {
    let e = engine("format='elixir_syslog'\nextends=['kbrw/elixir@^1']\n");
    let input = big_input(20_000);
    let cancel = AtomicBool::new(false);
    let mut out = Vec::new();
    let opts = RunOptions { batch_bytes: 8 << 10, ..Default::default() };
    let r = run(input.as_bytes(), &e, &mut out, &opts, &cancel, &mut |_| cancel.store(true, Ordering::Relaxed));
    assert!(matches!(r, Err(CoreError::Cancelled)));
}

#[test]
fn invalid_utf8_passes_through_untouched() {
    let e = engine("format='plain'\nextends=['kbrw/common@^1']\n");
    let mut input = b"bytes \xff\xfe then jean@example.com \xc3".to_vec();
    input.push(b'\n');
    let mut out = Vec::new();
    run(&input[..], &e, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    assert!(out.starts_with(b"bytes \xff\xfe then EMAIL_"));
    assert!(out.ends_with(b" \xc3\n"));
}

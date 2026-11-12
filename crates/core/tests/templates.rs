//! Les tests embarqués des templates fournis doivent passer.

// Ces tests s'appuient sur les templates et le corpus, qui ne font pas partie du dépôt.
#![cfg(logano_templates)]

use logano_core::template::testing::run_tests;
use logano_core::Library;

fn check(id: &str) {
    let lib = Library::builtin();
    let outcomes = run_tests(&lib, id).unwrap_or_else(|e| panic!("{id} : {e}"));
    assert!(!outcomes.is_empty(), "{id} n'a aucun test");
    let mut report = String::new();
    for o in outcomes.iter().filter(|o| !o.passed) {
        report.push_str(&format!("\n── {id} · {} ──\n", o.name));
        for f in &o.failures {
            report.push_str(&format!("  ✗ {f}\n"));
        }
        report.push_str(&format!("  sortie :\n{}\n", o.output));
    }
    assert!(report.is_empty(), "{report}");
}

#[test]
fn kbrw_common() {
    check("kbrw/common");
}

#[test]
fn kbrw_elixir() {
    check("kbrw/elixir");
}

#[test]
fn etam_gateway() {
    check("etam/gateway");
}

#[test]
fn etam_services() {
    check("etam/services");
}

#[test]
fn kbrw_haproxy() {
    check("kbrw/haproxy");
}

#[test]
fn kbrw_riak_console() {
    check("kbrw/riak-console");
}

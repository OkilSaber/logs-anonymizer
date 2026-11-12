//! Tests « golden file » : chaque `corpus/<template>/<cas>.in.log` doit donner exactement
//! `<cas>.out.log`. `UPDATE_GOLDEN=1 cargo test -p logano-core --test golden` régénère les
//! sorties attendues, à relire avant de les valider.

// Ces tests s'appuient sur les templates et le corpus, qui ne font pas partie du dépôt.
#![cfg(logano_templates)]

use logano_core::pipeline::{run, RunOptions};
use logano_core::template::testing::TEST_KEY;
use logano_core::{Engine, EngineOptions, Library};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn anonymize(template: &str, input: &[u8]) -> Vec<u8> {
    let lib = Library::builtin();
    let engine = Engine::new(Arc::new(lib.compile(template).unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap();
    let mut out = Vec::new();
    run(input, &engine, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    out
}

#[test]
fn corpus_matches_golden_outputs() {
    let update = std::env::var("UPDATE_GOLDEN").is_ok();
    let mut cases = 0;
    let mut diffs = String::new();
    for dir in std::fs::read_dir(corpus_dir()).unwrap().flatten().filter(|d| d.path().is_dir()) {
        // `kbrw-elixir` → `kbrw/elixir`
        let template = dir.file_name().to_string_lossy().replacen('-', "/", 1);
        for file in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let path = file.path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let Some(case) = name.strip_suffix(".in.log") else { continue };
            cases += 1;
            let actual = anonymize(&template, &std::fs::read(&path).unwrap());
            let expected_path = path.with_file_name(format!("{case}.out.log"));
            if update {
                std::fs::write(&expected_path, &actual).unwrap();
                continue;
            }
            let expected = std::fs::read(&expected_path).unwrap_or_default();
            if actual != expected {
                diffs.push_str(&format!(
                    "\n── {template} · {case} ──\n--- attendu\n{}\n--- obtenu\n{}\n",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
        }
    }
    assert!(cases >= 6, "corpus introuvable");
    assert!(diffs.is_empty(), "{diffs}");
}

#[test]
fn golden_outputs_contain_no_sensitive_value_from_the_inputs() {
    let sensitive = [
        "jean.dupont", "JEAN.DUPONT", "a.martin@", "b.durand@", "dXNlcjpwYXNzd29yZA", "AbCdEfGhIjKlMnOpQrStUvWxYz0", "eyJ0eXAi",
        "203.0.113.10", "DUPONT", "Dupont", "\"Jean\"", "1 rue de l'Exemple", "75000", "Paris", "0600000000", "11111111", "XXXXXXXXXXXXXXXX",
        // haproxy.log : IP clientes, IP publiques des frontends et des en-têtes capturés, jetons d'URL.
        "@example.", "198.51.100.", "51_75_10_28", "188_165_78_170", "51.75.11.123", "PHNhbWxw", "hunter22", "jdupont",
        "\u{1b}", "\r",
    ];
    for dir in std::fs::read_dir(corpus_dir()).unwrap().flatten().filter(|d| d.path().is_dir()) {
        for file in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let path = file.path();
            if !path.to_string_lossy().ends_with(".out.log") {
                continue;
            }
            let out = std::fs::read_to_string(&path).unwrap();
            for s in sensitive {
                assert!(!out.contains(s), "{} contient encore « {s} »", path.display());
            }
        }
    }
}

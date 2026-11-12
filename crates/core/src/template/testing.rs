//! Tests embarqués des templates.

use super::library::Library;
use crate::engine::{Engine, EngineOptions, Outcome, Scratch};
use crate::error::Result;
use crate::pipeline::{assemble_all, write_entry, Layout};
use serde::Serialize;
use std::sync::Arc;

/// Clé fixe : les jetons des tests sont stables d'une exécution à l'autre.
pub const TEST_KEY: [u8; 32] = *b"logano-template-tests-fixed-key!";

#[derive(Clone, Debug, Serialize)]
pub struct TestOutcome {
    pub name: String,
    pub passed: bool,
    pub failures: Vec<String>,
    /// Sortie anonymisée produite (disposition compacte).
    pub output: String,
}

/// Lance les `[[tests]]` d'un template, héritage résolu.
pub fn run_tests(lib: &Library, id: &str) -> Result<Vec<TestOutcome>> {
    let tpl = Arc::new(lib.compile(id)?);
    let file = lib.get(id).expect("compilé, donc présent");
    let mut outcomes = Vec::new();
    for test in &file.tests {
        // Un moteur neuf par test : aucun état (registre de jetons) ne passe de l'un à l'autre.
        let engine = Engine::new(tpl.clone(), EngineOptions::with_key(TEST_KEY))?;
        let mut stats = engine.new_stats();
        let mut sc = Scratch::default();
        let mut out = Vec::new();
        let mut text = Vec::new();
        let entries = assemble_all(&engine, test.input.as_bytes());
        let mut kept = 0;
        for entry in &entries {
            text.clear();
            if let Outcome::Kept { .. } = engine.process(entry, &mut sc, &mut text, &mut stats, None) {
                write_entry(Layout::Compact, &entry.source, &text, &mut out);
                kept += 1;
            }
        }
        let output = String::from_utf8_lossy(&out).into_owned();
        let mut failures = Vec::new();
        if let Some(expected) = &test.expected {
            if output.trim_matches('\n') != expected.trim_matches('\n') {
                failures.push(format!("sortie différente de expected :\n{}", output.trim_matches('\n')));
            }
        }
        for needle in &test.expect_contains {
            if !output.contains(needle.as_str()) {
                failures.push(format!("absent de la sortie : « {needle} »"));
            }
        }
        for needle in &test.expect_not_contains {
            if output.contains(needle.as_str()) {
                failures.push(format!("présent dans la sortie : « {needle} »"));
            }
        }
        match test.expect_dropped {
            Some(true) if kept > 0 => failures.push(format!("{kept} entrée(s) gardée(s), aucune attendue")),
            Some(false) if kept != entries.len() => failures.push(format!("{} entrée(s) supprimée(s), aucune attendue", entries.len() - kept)),
            _ => {}
        }
        if entries.is_empty() {
            failures.push("l'entrée du test ne contient aucune ligne".to_string());
        }
        outcomes.push(TestOutcome { name: test.name.clone(), passed: failures.is_empty(), failures, output });
    }
    Ok(outcomes)
}

//! Anonymise des fichiers de log locaux vers une sortie, hors de l'app.
//! Sert à rejouer un template sur le cache brut.
//!
//! `cargo run --release -p logano-core --example anonymize -- <template> <compact|faithful> <sortie> <entrée>...`
//!
//! N'affiche que des compteurs : aucune ligne de log.

use logano_core::pipeline::{open_input, run, Layout, RunOptions};
use logano_core::{Engine, EngineOptions, Library};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// `…/2026/11/05/…` → `2026-11-05`
fn day_of(path: &Path) -> Option<String> {
    let parts: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let digits = |s: &String, n: usize| s.len() == n && s.chars().all(|c| c.is_ascii_digit());
    parts.windows(3).find(|w| digits(&w[0], 4) && digits(&w[1], 2) && digits(&w[2], 2)).map(|w| format!("{}-{}-{}", w[0], w[1], w[2]))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        return Err("usage : anonymize <template> <compact|faithful> <sortie> <entrée>...".into());
    }
    let layout = if args[1] == "faithful" { Layout::Faithful } else { Layout::Compact };
    let lib = Library::builtin();
    let tpl = Arc::new(lib.compile(&args[0])?);
    let key: [u8; 32] = std::array::from_fn(|_| rand_byte());
    let engine = Engine::new(tpl.clone(), EngineOptions::with_key(key))?;
    if let Some(dir) = Path::new(&args[2]).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut out = BufWriter::with_capacity(1 << 20, std::fs::File::create(&args[2])?);
    let mut total = engine.new_stats();
    for input in &args[3..] {
        let path = Path::new(input);
        writeln!(out, "# logs anonymisés · jour={} · template={}@{}", day_of(path).unwrap_or_else(|| "?".into()), tpl.id, tpl.version)?;
        let opts = RunOptions { layout, ..Default::default() };
        let stats = run(open_input(path)?, &engine, &mut out, &opts, &AtomicBool::new(false), &mut |_| {})?;
        total.merge(stats);
    }
    out.flush()?;
    println!(
        "entrées lues={} gardées={} filtrées={} modifiées={} · brut={} Mo sortie={} Mo · filet={}",
        total.entries_in,
        total.entries_out,
        total.dropped,
        total.modified,
        total.bytes_in >> 20,
        total.bytes_out >> 20,
        total.safety_total()
    );
    if let Some(e) = &total.input_error {
        println!("  lecture interrompue : {e}");
    }
    for (d, n) in logano_core::detect::DetectorId::ALL.iter().zip(&total.safety_hits).filter(|(_, n)| **n > 0) {
        println!("  filet  {:42} {n}", d.as_str());
    }
    for (i, f) in tpl.filters.iter().enumerate().filter(|(i, _)| total.filter_hits[*i] > 0) {
        println!("  filtre {:42} {}", f.id, total.filter_hits[i]);
    }
    for (i, r) in tpl.rules.iter().enumerate().filter(|(i, _)| total.rule_hits[*i] > 0) {
        println!("  règle  {:42} {}", r.id, total.rule_hits[i]);
    }
    Ok(())
}

/// Octet aléatoire depuis le système : la clé du run n'a pas à être reproductible.
fn rand_byte() -> u8 {
    use std::io::Read;
    let mut b = [0u8; 1];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    b[0]
}

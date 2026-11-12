//! Mesure le débit du moteur sur un corpus synthétique construit depuis le corpus golden.
//!
//! `cargo run --release -p logano-core --example throughput -- 512`  (taille en Mo)
//! `cargo run --release -p logano-core --example throughput -- 512 kbrw/haproxy`

use logano_core::format::FormatKind;
use logano_core::pipeline::{run, RunOptions};
use logano_core::{Engine, EngineOptions, Library};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let mb: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(256);
    let template = std::env::args().nth(2).unwrap_or_else(|| "etam/gateway".to_string());
    let lib = Library::builtin();
    let compiled = lib.compile(&template).unwrap();
    // Le corpus suit le format du template.
    let read = |name: &str| {
        std::fs::read_to_string(format!("{}/../../corpus/{name}", env!("CARGO_MANIFEST_DIR"))).expect("corpus introuvable : il accompagne les templates, hors du dépôt")
    };
    let seeds: Vec<String> = match compiled.format {
        FormatKind::HaproxySyslog => vec![read("kbrw-haproxy/prompt-examples.in.log"), read("kbrw-haproxy/variants.in.log")],
        FormatKind::LagerSyslog => vec![read("kbrw-riak-console/prompt-examples.in.log"), read("kbrw-riak-console/variants.in.log")],
        _ => vec![read("kbrw-elixir/prompt-examples.in.log"), read("etam-gateway/order-payload.in.log")],
    };
    // Varie les emails, les numéros et les IP clientes pour que les jetons ne soient pas tous identiques.
    let mut input = Vec::with_capacity(mb << 20);
    let mut i = 0usize;
    while input.len() < mb << 20 {
        for seed in &seeds {
            let varied = seed
                .replace("jean.dupont", &format!("user{}", i % 5000))
                .replace("900449662", &format!("9{:08}", i))
                .replace("198.51.100.", &format!("198.51.{}.", i % 250));
            input.extend_from_slice(varied.as_bytes());
        }
        i += 1;
    }
    let engine = Engine::new(Arc::new(compiled), EngineOptions::with_key([3; 32])).unwrap();
    let start = Instant::now();
    let mut sink = std::io::sink();
    let stats = run(&input[..], &engine, &mut sink, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{template} : {:.0} Mo en {secs:.2} s = {:.0} Mo/s · {} entrées lues, {} gardées, {} modifiées, filet {}",
        input.len() as f64 / 1048576.0,
        input.len() as f64 / 1048576.0 / secs,
        stats.entries_in,
        stats.entries_out,
        stats.modified,
        stats.safety_total()
    );
}

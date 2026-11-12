//! Profile un fichier de log avec un template : formes d'entrées par poids et inventaire
//! des clés. C'est la fonction qu'appelle l'écran Profil de l'app.
//!
//! `cargo run --release -p logano-core --example profile -- <template> <fichier> [nombre]`
//!
//! N'affiche que des formes masquées et des comptes : aucune valeur.

use logano_core::pipeline::open_input;
use logano_core::profile::{profile, ProfileOptions};
use logano_core::{Engine, EngineOptions, Library};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err("usage : profile <template> <fichier> [nombre]".into());
    }
    let top: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);
    let lib = Library::builtin();
    let engine = Engine::new(Arc::new(lib.compile(&args[0])?), EngineOptions::with_key([5; 32]))?;
    let start = Instant::now();
    let p = profile(open_input(Path::new(&args[1]))?, &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {})?;
    let pct = |part: u64, total: u64| if total == 0 { 0.0 } else { part as f64 / total as f64 * 100.0 };
    println!(
        "{} entrées · {:.2} Go · {:.1} % déjà filtrés · {} formes · {} clés · {:.1} s",
        p.entries,
        p.bytes as f64 / 1e9,
        pct(p.filtered_bytes, p.bytes),
        p.shapes_total,
        p.keys_total,
        start.elapsed().as_secs_f64()
    );
    println!("--- formes les plus lourdes");
    for s in p.shapes.iter().take(top) {
        let shape: String = s.shape.chars().take(88).collect();
        let filter = match &s.filtered_by {
            Some(f) if s.filtered_count == s.count => f.clone(),
            Some(f) => format!("{f} ({} sur {})", s.filtered_count, s.count),
            None => String::new(),
        };
        println!("{:5.1} % {:>9}x [{:5}] {:<88} {filter}", pct(s.bytes, p.bytes), s.count, s.level, shape.replace('\t', " "));
    }
    println!("--- clés qui gardent des valeurs en clair");
    for k in p.keys.iter().filter(|k| k.count > k.replaced).take(top) {
        let shapes: Vec<String> = k.shapes.iter().take(3).map(|(s, n)| format!("{s}×{n}")).collect();
        println!("{:<44} {:>8} en clair sur {:>8} · {:>6} distinctes · {}", k.path, k.count - k.replaced, k.count, k.distinct, shapes.join("  "));
    }
    Ok(())
}

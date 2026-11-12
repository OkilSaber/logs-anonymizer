//! Lance les tests embarqués d'un template et affiche les sorties produites.
//!
//! `cargo run -p logano-core --example template_tests -- etam/gateway`

use logano_core::template::testing::run_tests;
use logano_core::Library;

fn main() {
    let lib = Library::builtin();
    let ids: Vec<String> = match std::env::args().nth(1) {
        Some(id) => vec![id],
        None => lib.ids().map(String::from).collect(),
    };
    let mut failed = 0;
    for id in ids {
        match run_tests(&lib, &id) {
            Err(e) => println!("== {id} : {e}"),
            Ok(outcomes) => {
                for o in outcomes {
                    println!("== {id} · {} : {}", o.name, if o.passed { "ok" } else { "ÉCHEC" });
                    for f in &o.failures {
                        failed += 1;
                        println!("   ✗ {f}");
                    }
                    print!("{}", o.output);
                }
            }
        }
    }
    std::process::exit(if failed > 0 { 1 } else { 0 });
}

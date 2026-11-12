//! Embarque les templates du dossier `templates/` du dépôt, quand il existe et que la
//! fonctionnalité `embedded-templates` est activée. Les templates ne font pas partie du
//! dépôt : l'app distribuée n'en contient aucun, on les importe depuis l'interface.
//!
//! Émet `cfg(logano_templates)` quand au moins un template est embarqué : les tests qui
//! s'appuient sur eux ne sont compilés que dans ce cas.

use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "toml") {
            out.push(path);
        }
    }
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(logano_templates)");
    println!("cargo:rerun-if-changed=build.rs");
    let dir = Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR")).join("../../templates");
    let mut files = Vec::new();
    if std::env::var_os("CARGO_FEATURE_EMBEDDED_TEMPLATES").is_some() && dir.is_dir() {
        println!("cargo:rerun-if-changed={}", dir.display());
        collect(&dir, &mut files);
    }
    files.sort();
    if !files.is_empty() {
        println!("cargo:rustc-cfg=logano_templates");
    }
    let list: String = files
        .iter()
        .map(|p| format!("    include_str!({:?}),\n", p.canonicalize().expect("chemin de template").display().to_string()))
        .collect();
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("builtin_templates.rs");
    std::fs::write(out, format!("&[\n{list}]\n")).expect("écriture de la liste des templates");
}

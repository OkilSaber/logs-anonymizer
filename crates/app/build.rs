//! `cfg(logano_templates)` : le dossier `templates/` du dépôt existe. Les tests de l'app qui
//! s'appuient sur des templates ne sont compilés que dans ce cas (voir `crates/core/build.rs`).

fn has_templates(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            let path = e.path();
            if path.is_dir() { has_templates(&path) } else { path.extension().is_some_and(|x| x == "toml") }
        })
    })
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(logano_templates)");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates");
    if has_templates(&dir) {
        println!("cargo:rerun-if-changed={}", dir.display());
        println!("cargo:rustc-cfg=logano_templates");
    }
    tauri_build::build()
}

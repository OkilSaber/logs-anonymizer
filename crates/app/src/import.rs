//! Import de templates en lot : plusieurs `.toml`, un dossier, ou une archive `.zip`.
//!
//! Rien n'est extrait sur le disque : chaque `.toml` est lu en mémoire, validé (schéma,
//! héritage, compilation, tests embarqués), puis écrit sous son identifiant dans le dossier
//! des templates de l'utilisateur. Un lot peut contenir un template et ses parents, dans
//! n'importe quel ordre.

use crate::commands::check_in_library;
use crate::dto::{ImportReport, ImportedTemplate, RejectedTemplate};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Au-delà, ce n'est pas un template.
const MAX_TEMPLATE_BYTES: u64 = 4 << 20;
/// Garde-fou contre un dossier ou une archive qui ne sont pas des lots de templates.
const MAX_FILES: usize = 500;
const MAX_ZIP_ENTRIES: usize = 5000;

/// Un fichier candidat : d'où il vient, et son texte ou la raison pour laquelle il est illisible.
pub struct Source {
    pub label: String,
    pub text: Result<String, String>,
}

fn read_capped(reader: impl Read) -> Result<String, String> {
    let mut buf = Vec::new();
    reader.take(MAX_TEMPLATE_BYTES + 1).read_to_end(&mut buf).map_err(|e| format!("lecture impossible : {e}"))?;
    if buf.len() as u64 > MAX_TEMPLATE_BYTES {
        return Err("plus de 4 Mo : ce n'est pas un template".into());
    }
    String::from_utf8(buf).map_err(|_| "ce n'est pas du texte UTF-8".into())
}

fn is_toml(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".toml")
}

fn too_many() -> AppError {
    AppError::new("too_large", format!("Plus de {MAX_FILES} fichiers .toml : ce n'est pas un lot de templates."))
}

fn push(out: &mut Vec<Source>, label: String, text: Result<String, String>) -> AppResult<()> {
    if out.len() >= MAX_FILES {
        return Err(too_many());
    }
    out.push(Source { label, text });
    Ok(())
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

/// Tous les `.toml` d'un dossier, récursivement. Fichiers cachés et liens symboliques ignorés.
fn collect_dir(root: &Path, out: &mut Vec<Source>) -> AppResult<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)?.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let name = file_name(&path);
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if name.starts_with('.') || meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if is_toml(&name) {
                let label = path.strip_prefix(root).unwrap_or(&path).display().to_string();
                push(out, label, std::fs::File::open(&path).map_err(|e| format!("lecture impossible : {e}")).and_then(read_capped))?;
            }
        }
    }
    Ok(())
}

/// Tous les `.toml` d'une archive, lus en mémoire. Les métadonnées de macOS (`__MACOSX/`,
/// `._fichier`) sont ignorées.
fn collect_zip(path: &Path, out: &mut Vec<Source>) -> AppResult<()> {
    let zip_name = file_name(path);
    let invalid = |e: zip::result::ZipError| AppError::new("template_invalid", format!("{zip_name} n'est pas une archive .zip lisible : {e}"));
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path)?).map_err(invalid)?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(AppError::new("too_large", format!("{zip_name} contient plus de {MAX_ZIP_ENTRIES} entrées : ce n'est pas un lot de templates.")));
    }
    for i in 0..archive.len() {
        let entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(e) => {
                push(out, format!("{zip_name} › entrée {i}"), Err(format!("entrée illisible : {e}")))?;
                continue;
            }
        };
        let name = entry.name().to_string();
        let base = name.rsplit('/').next().unwrap_or("");
        if entry.is_dir() || !is_toml(&name) || base.starts_with('.') || name.starts_with("__MACOSX/") {
            continue;
        }
        push(out, format!("{zip_name} › {name}"), read_capped(entry))?;
    }
    Ok(())
}

/// Rassemble les candidats : chaque chemin est un dossier, une archive `.zip` ou un `.toml`.
pub fn collect(paths: &[PathBuf]) -> AppResult<Vec<Source>> {
    let mut out = Vec::new();
    for path in paths {
        let name = file_name(path);
        if path.is_dir() {
            collect_dir(path, &mut out)?;
        } else if name.to_ascii_lowercase().ends_with(".zip") {
            collect_zip(path, &mut out)?;
        } else if is_toml(&name) {
            push(&mut out, name, std::fs::File::open(path).map_err(|e| format!("lecture impossible : {e}")).and_then(read_capped))?;
        } else {
            push(&mut out, name, Err("ni un .toml ni un .zip".into()))?;
        }
    }
    Ok(out)
}

/// Valide le lot puis enregistre les templates acceptés. Un template refusé n'empêche pas
/// les autres ; un template dont un parent est refusé ou absent est refusé lui aussi.
pub fn import(state: &AppState, sources: Vec<Source>) -> AppResult<ImportReport> {
    let current = state.library.read().expect("verrou bibliothèque").clone();
    let mut rejected = Vec::new();

    // 1. Tout le lot dans une copie de la bibliothèque : l'ordre des fichiers n'importe pas.
    let mut batch = current.clone();
    let mut candidates: Vec<(String, String, String)> = Vec::new(); // (id, provenance, texte)
    for Source { label, text } in sources {
        let text = match text {
            Ok(text) => text,
            Err(reason) => {
                rejected.push(RejectedTemplate { source: label, reason });
                continue;
            }
        };
        match batch.add_str(&text) {
            Ok(id) if current.is_builtin(&id) => {
                rejected.push(RejectedTemplate { source: label, reason: format!("« {id} » est fourni avec l'app : il ne se remplace pas.") });
            }
            Ok(id) => {
                // Deux fichiers pour le même identifiant : le dernier lu l'emporte.
                if let Some(pos) = candidates.iter().position(|(other, _, _)| *other == id) {
                    let (_, source, _) = candidates.remove(pos);
                    rejected.push(RejectedTemplate { source, reason: format!("« {id} » est aussi dans {label}, qui l'emporte.") });
                }
                candidates.push((id, label, text));
            }
            Err(e) => rejected.push(RejectedTemplate { source: label, reason: e.to_string() }),
        }
    }

    // 2. Chaque template compile et passe ses tests, avec ses parents du lot.
    let mut accepted: Vec<(String, String, String, u32)> = Vec::new();
    for (id, label, text) in candidates {
        let check = check_in_library(&current, &batch, &id);
        if check.ok {
            accepted.push((id, label, text, check.weakens.len() as u32));
        } else {
            let failed: Vec<&str> = check.tests.iter().filter(|t| !t.passed).map(|t| t.name.as_str()).collect();
            let mut reason = check.error.unwrap_or_else(|| "Template invalide.".into());
            if !failed.is_empty() {
                reason = format!("{reason} ({})", failed.join(", "));
            }
            rejected.push(RejectedTemplate { source: label, reason });
        }
    }

    // 3. Un template accepté doit encore se résoudre sans les refusés : on retire ceux dont
    //    un parent manque, jusqu'à ce que plus rien ne bouge.
    loop {
        let mut kept = current.clone();
        for (_, _, text, _) in &accepted {
            kept.add_str(text).expect("déjà validé");
        }
        let before = accepted.len();
        accepted.retain(|(id, label, _, _)| match kept.compile(id) {
            Ok(_) => true,
            Err(e) => {
                rejected.push(RejectedTemplate { source: label.clone(), reason: format!("Un parent est refusé ou absent : {e}") });
                false
            }
        });
        if accepted.len() == before {
            break;
        }
    }

    // 4. Écriture, puis rechargement de la bibliothèque depuis le disque.
    let mut imported = Vec::new();
    for (id, _, text, weakens) in accepted {
        let path = crate::local::user_path(state, &id);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, text)?;
        imported.push(ImportedTemplate { replaced: current.get(&id).is_some(), id, weakens });
    }
    crate::local::refresh(state);
    imported.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(ImportReport { imported, rejected })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Dirs;
    use std::io::Write;

    fn state(name: &str) -> (AppState, PathBuf) {
        let root = std::env::temp_dir().join(format!("logano-import-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs = Dirs { data: root.join("data"), raw_cache: root.join("cache"), default_output: root.join("out") };
        let state = AppState::init(dirs).unwrap();
        // Ces tests portent leurs propres templates : ils ne dépendent pas de ceux du dépôt.
        *state.library.write().unwrap() = logano_core::Library::default();
        (state, root)
    }

    const BASE: &str = r#"
[template]
id = "demo/socle"
name = "Socle de démo"
version = "1.0.0"
schema_version = 1
log_kind = "erlang"
format = "elixir_syslog"

[[rules]]
id = "emails"
detector = "email"
strategy = "pseudonymize"
token = "EMAIL"

[[tests]]
name = "email pseudonymisé"
input = '''
h.example.com  10:00:00.000 [info]  owner jean@example.com not found
'''
expect_contains = ["owner EMAIL_"]
expect_not_contains = ["jean@example.com"]
"#;

    const CHILD: &str = r#"
[template]
id = "demo/app"
name = "App de démo"
version = "1.0.0"
schema_version = 1
log_kind = "erlang"
format = "elixir_syslog"
extends = ["demo/socle@^1"]
suggested_apps = ["demo_*"]

[[rules]]
id = "order-ids"
keys = ["order_ref"]
strategy = "keep"
"#;

    fn zip_of(path: &Path, files: &[(&str, &str)]) {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, content) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            zip.write_all(content.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn ids(report: &ImportReport) -> Vec<&str> {
        report.imported.iter().map(|t| t.id.as_str()).collect()
    }

    #[test]
    fn a_zip_brings_a_template_and_its_parent_in_any_order() {
        let (state, root) = state("zip");
        let archive = root.join("lot.zip");
        zip_of(
            &archive,
            &[
                ("templates/demo/app.toml", CHILD),
                ("templates/demo/socle.toml", BASE),
                ("templates/LISEZ-MOI.txt", "pas un template"),
                ("__MACOSX/templates/demo/._app.toml", "métadonnées"),
                ("templates/casse.toml", "[template\nid = "),
            ],
        );
        let report = import(&state, collect(&[archive]).unwrap()).unwrap();
        assert_eq!(ids(&report), ["demo/app", "demo/socle"]);
        assert!(report.imported.iter().all(|t| !t.replaced));
        // La règle « keep » de l'app affaiblit la protection : elle est signalée.
        assert_eq!(report.imported[0].weakens, 1);
        assert_eq!(report.rejected.len(), 1, "{:?}", report.rejected);
        assert_eq!(report.rejected[0].source, "lot.zip › templates/casse.toml");

        let lib = state.library.read().unwrap().clone();
        assert!(lib.compile("demo/app").is_ok());
        assert!(crate::local::user_path(&state, "demo/app").exists());
        assert_eq!(crate::state::pick_template(&lib, &crate::config::AppConfig::default(), "demo_services", "erlang", None).as_deref(), Some("demo/app"));

        // Un second import remplace, et le dit.
        let again = import(&state, collect(&[root.join("lot.zip")]).unwrap()).unwrap();
        assert!(again.imported.iter().all(|t| t.replaced));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_folder_and_loose_files_are_imported_too() {
        let (state, root) = state("dossier");
        let dir = root.join("partage");
        std::fs::create_dir_all(dir.join("demo")).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join("demo/socle.toml"), BASE).unwrap();
        std::fs::write(dir.join(".git/config.toml"), "ignoré").unwrap();
        let loose = root.join("app.toml");
        std::fs::write(&loose, CHILD).unwrap();
        let other = root.join("notes.md");
        std::fs::write(&other, "x").unwrap();

        let report = import(&state, collect(&[dir, loose, other]).unwrap()).unwrap();
        assert_eq!(ids(&report), ["demo/app", "demo/socle"]);
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].source, "notes.md");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_child_without_a_valid_parent_is_refused_and_nothing_is_written() {
        let (state, root) = state("orphelin");
        let orphan = root.join("app.toml");
        std::fs::write(&orphan, CHILD).unwrap();
        let report = import(&state, collect(std::slice::from_ref(&orphan)).unwrap()).unwrap();
        assert!(report.imported.is_empty() && report.rejected.len() == 1);

        // Le parent est dans le lot mais ses tests échouent : les deux sont refusés.
        let broken = root.join("socle.toml");
        std::fs::write(&broken, BASE.replace("owner EMAIL_", "owner JAMAIS_")).unwrap();
        let report = import(&state, collect(&[orphan, broken]).unwrap()).unwrap();
        assert!(report.imported.is_empty(), "{:?}", ids(&report));
        assert_eq!(report.rejected.len(), 2);
        assert!(!state.dirs.user_templates().join("demo").exists());
        let lib = state.library.read().unwrap().clone();
        assert!(lib.get("demo/app").is_none() && lib.get("demo/socle").is_none());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_identifier_cannot_point_outside_the_templates_folder() {
        let (state, root) = state("chemin");
        for id in ["/tmp/evasion", "demo//x", "demo/"] {
            let file = root.join("x.toml");
            std::fs::write(&file, BASE.replace("demo/socle", id)).unwrap();
            let report = import(&state, collect(&[file]).unwrap()).unwrap();
            assert!(report.imported.is_empty() && report.rejected.len() == 1, "{id}");
        }
        std::fs::remove_dir_all(&root).ok();
    }
}

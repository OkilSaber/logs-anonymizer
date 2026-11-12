//! Historique des runs : métadonnées seulement (serveur, apps, jours, templates, compteurs),
//! jamais de contenu de log. Sert à rejouer un run en un clic.

use crate::dto::{HistoryEntry, HistoryFile, PlanRequest, RunDone};
use crate::error::AppResult;
use std::path::Path;

const MAX_ENTRIES: usize = 200;

pub fn load(path: &Path) -> Vec<HistoryEntry> {
    std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
}

fn save(path: &Path, entries: &[HistoryEntry]) -> AppResult<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(entries).unwrap_or_default())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Ajoute un run terminé en tête de l'historique.
pub fn record(path: &Path, started_at: &str, request: &PlanRequest, done: &RunDone) -> AppResult<()> {
    let mut entries = load(path);
    entries.insert(
        0,
        HistoryEntry {
            run_id: done.run_id.clone(),
            started_at: started_at.to_string(),
            request: request.clone(),
            outcome: if done.cancelled { "cancelled" } else if done.error.is_some() { "error" } else { "ok" }.to_string(),
            error: done.error.as_ref().map(|e| e.message.clone()),
            files: done
                .files
                .iter()
                .map(|f| HistoryFile {
                    app: f.app.clone(),
                    cluster: f.cluster.clone(),
                    kind: f.kind.clone(),
                    template: format!("{}@{}", f.template, f.template_version),
                    entries_in: f.entries_in,
                    entries_out: f.entries_out,
                    bytes_out: f.bytes_out,
                    safety_total: f.safety_total,
                })
                .collect(),
        },
    );
    entries.truncate(MAX_ENTRIES);
    save(path, &entries)
}

pub fn clear(path: &Path) -> AppResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{FileResult, Selection};

    #[test]
    fn records_newest_first_and_keeps_only_metadata() {
        let dir = std::env::temp_dir().join(format!("logano-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("history.json");
        assert!(load(&path).is_empty());
        let request = PlanRequest {
            server_id: "etam-sb".into(),
            days: vec!["2026-11-09".into(), "2026-11-10".into()],
            selections: vec![Selection { app: "etam_sb_services".into(), clusters: vec!["etam-sb".into()] }],
            kinds: vec!["erlang".into()],
            template: None,
        };
        let file = FileResult {
            output_id: "r1/x".into(),
            days: request.days.clone(),
            app: "etam_sb_services".into(),
            cluster: "etam-sb".into(),
            kind: "erlang".into(),
            template: "etam/services".into(),
            template_version: "1.0.0".into(),
            output_path: "/tmp/x".into(),
            parts: vec![],
            deduplicated: 0,
            entries_in: 100,
            entries_out: 40,
            dropped: 60,
            modified: 5,
            bytes_in: 1000,
            bytes_out: 400,
            safety_total: 1,
            findings: vec![],
            rules: vec![],
            filters: vec![],
            warnings: vec![],
            quarantined: false,
        };
        let done = |id: &str, cancelled: bool| RunDone { run_id: id.into(), cancelled, error: None, files: vec![file.clone()], skipped: vec![], mapping_tokens: 0 };
        record(&path, "2026-11-11T00:57:49+01:00", &request, &done("r1", false)).unwrap();
        record(&path, "2026-11-11T01:10:00+01:00", &request, &done("r2", true)).unwrap();
        let entries = load(&path);
        assert_eq!(entries.iter().map(|e| (e.run_id.as_str(), e.outcome.as_str())).collect::<Vec<_>>(), vec![("r2", "cancelled"), ("r1", "ok")]);
        assert_eq!(entries[1].files[0].template, "etam/services@1.0.0");
        assert_eq!(entries[1].request.days.len(), 2);
        clear(&path).unwrap();
        assert!(load(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}

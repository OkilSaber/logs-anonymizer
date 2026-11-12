//! Orchestration d'un run : fichiers à traiter, téléchargement vers le cache brut,
//! anonymisation vers le dossier des sorties.

use crate::dto::{Counter, FileResult, FindingDto, PartInfo, PlanFile, PlanRequest, RunDone, RunProgress};
use crate::error::{AppError, AppResult};
use crate::state::{pick_template, AppState, OutputInfo};
use chrono::NaiveDate;
use logano_core::engine::SafetyAction;
use logano_core::format::make_format;
use futures_util::stream::{FuturesUnordered, StreamExt};
use logano_core::output::{PartWriter, BYTES_PER_TOKEN};
use logano_core::pipeline::{open_input_counted, run_to_sink, Layout, RunOptions};
use logano_core::{Engine, EngineOptions, Stats};
use logano_remote::{CancellationToken, LogKind, RawCache, RemoteError, RemoteFile, RemoteSession};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Manager};
use tauri_specta::Event;

pub const MAX_DAYS: usize = 366;

/// Jours demandés, triés et dédoublonnés.
pub fn parse_days(days: &[String]) -> AppResult<Vec<NaiveDate>> {
    let mut parsed = days
        .iter()
        .map(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|_| AppError::new("invalid_day", format!("Jour invalide : « {d} » (attendu AAAA-MM-JJ).")))) 
        .collect::<AppResult<Vec<_>>>()?;
    parsed.sort();
    parsed.dedup();
    if parsed.is_empty() {
        return Err(AppError::new("invalid_day", "Aucun jour sélectionné."));
    }
    if parsed.len() > MAX_DAYS {
        return Err(AppError::new("invalid_day", format!("{} jours demandés : {MAX_DAYS} au plus par run.", parsed.len())));
    }
    Ok(parsed)
}

/// Laisse passer au plus un appel toutes les 100 ms.
struct Throttle {
    start: Instant,
    last_ms: AtomicU64,
}

impl Throttle {
    fn new() -> Self {
        Throttle { start: Instant::now(), last_ms: AtomicU64::new(0) }
    }

    fn ready(&self) -> bool {
        let now = self.start.elapsed().as_millis() as u64 + 100;
        let last = self.last_ms.load(Ordering::Relaxed);
        now >= last + 100 && self.last_ms.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    }
}

pub type Planned = (PlanFile, RemoteFile, NaiveDate);

/// Fichiers distants correspondant à la demande, jour par jour, avec leur template et leur
/// état de cache. Les sélections sans dossier ou sans fichier un jour donné sont rendues à
/// part, sans échec.
pub async fn collect_files(state: &AppState, session: &RemoteSession, cache: &RawCache, req: &PlanRequest) -> AppResult<(Vec<Planned>, Vec<String>)> {
    let days = parse_days(&req.days)?;
    let cfg = state.config();
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for day in days {
        for sel in &req.selections {
            for cluster in &sel.clusters {
                let listed = match session.list_files(day, &sel.app, cluster).await {
                    Ok(l) => l,
                    Err(RemoteError::FileNotFound { .. } | RemoteError::DayNotFound { .. }) => {
                        missing.push(format!("{day} · {}/{cluster} : aucun dossier", sel.app));
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let mut seen: Vec<LogKind> = Vec::new();
                // `.gz` d'abord : s'il existe, on ne prend pas le `.log` du même type.
                for rf in listed {
                    let kind = rf.kind.as_str().to_string();
                    if !req.kinds.contains(&kind) || seen.contains(&rf.kind) {
                        continue;
                    }
                    seen.push(rf.kind);
                    let forced = if kind == "erlang" { req.template.as_deref() } else { None };
                    let (template, problem) = {
                        let lib = state.library.read().expect("verrou bibliothèque");
                        match pick_template(&lib, &cfg, &sel.app, &kind, forced) {
                            None => (None, Some("aucun template pour ce type de log".to_string())),
                            Some(id) => match lib.compile(&id).and_then(|t| make_format(t.format).map(|_| ())) {
                                Ok(()) => (Some(id), None),
                                Err(e) => (Some(id), Some(e.to_string())),
                            },
                        }
                    };
                    let cached = cache.lookup(&req.server_id, day, &sel.app, cluster, &rf).is_valid();
                    files.push((
                        PlanFile {
                            day: day.to_string(),
                            app: sel.app.clone(),
                            cluster: cluster.clone(),
                            kind,
                            remote_path: rf.path.clone(),
                            size: rf.size,
                            compressed: rf.compressed,
                            cached,
                            template,
                            problem,
                        },
                        rf,
                        day,
                    ));
                }
                if seen.is_empty() {
                    missing.push(format!("{day} · {}/{cluster} : aucun fichier des types demandés", sel.app));
                }
            }
        }
    }
    Ok((files, missing))
}

fn file_result(output_id: &str, pf: &PlanFile, days: Vec<String>, engine: &Engine, stats: &Stats, paths: &[PathBuf], quarantined: bool) -> FileResult {
    let tpl = engine.template();
    let rules = tpl
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| Counter { id: r.id.clone(), hits: stats.rule_hits[i], shadowed: stats.shadowed[i] })
        .filter(|c| c.hits > 0 || c.shadowed > 0)
        .collect();
    let filters = tpl
        .filters
        .iter()
        .enumerate()
        .map(|(i, f)| Counter { id: f.id.clone(), hits: stats.filter_hits[i], shadowed: 0 })
        .filter(|c| c.hits > 0)
        .collect();
    let mut warnings = tpl.warnings.clone();
    if let Some(e) = &stats.input_error {
        warnings.push(format!("fichier tronqué ou corrompu, traité jusqu'à l'erreur : {e}"));
    }
    FileResult {
        output_id: output_id.to_string(),
        days,
        app: pf.app.clone(),
        cluster: pf.cluster.clone(),
        kind: pf.kind.clone(),
        template: tpl.id.clone(),
        template_version: tpl.version.clone(),
        output_path: paths.first().map(|p| p.display().to_string()).unwrap_or_default(),
        parts: paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let bytes = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                PartInfo { index: i as u32, path: p.display().to_string(), bytes, tokens: bytes / BYTES_PER_TOKEN }
            })
            .collect(),
        deduplicated: stats.deduplicated,
        entries_in: stats.entries_in,
        entries_out: stats.entries_out,
        dropped: stats.dropped,
        modified: stats.modified,
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
        safety_total: stats.safety_total(),
        findings: stats
            .findings
            .iter()
            .map(|f| FindingDto { detector: f.detector.to_string(), source: f.source.clone(), line_no: f.line_no, context: f.context.clone(), replaced: f.replaced })
            .collect(),
        rules,
        filters,
        warnings,
        quarantined,
    }
}

/// Ce qu'un run a produit, y compris s'il s'arrête sur une erreur.
#[derive(Default)]
struct RunOutput {
    files: Vec<FileResult>,
    skipped: Vec<String>,
    mapping_tokens: u64,
}

async fn run_inner(
    app: &AppHandle,
    state: &AppState,
    run_id: &str,
    req: &PlanRequest,
    token: &CancellationToken,
    flag: &Arc<AtomicBool>,
    output: &mut RunOutput,
) -> AppResult<()> {
    let RunOutput { files: results, skipped, mapping_tokens } = output;
    let progress = |file_index: usize, file_count: usize, label: &str, phase: &str, done: u64, total: u64, st: Option<&logano_core::Progress>| RunProgress {
        run_id: run_id.to_string(),
        file_index: file_index as u32,
        file_count: file_count as u32,
        label: label.to_string(),
        phase: phase.to_string(),
        bytes_done: done,
        bytes_total: total,
        processed_bytes: st.map_or(0, |s| s.bytes_in),
        entries_in: st.map_or(0, |s| s.entries_in),
        dropped: st.map_or(0, |s| s.dropped),
        modified: st.map_or(0, |s| s.modified),
        finished: false,
    };
    let _ = progress(0, 0, "Connexion", "connect", 0, 0, None).emit(app);

    let (server, session) = state.session(&req.server_id).await?;
    let cache = RawCache::new(&state.dirs.raw_cache);
    let (files, missing) = collect_files(state, &session, &cache, req).await?;
    skipped.extend(missing);

    let cfg = state.config();
    let out_root = state.dirs.output_root(&cfg).join(run_id);
    if out_root.starts_with(&state.dirs.raw_cache) {
        return Err(AppError::new("output_in_cache", "Le dossier des sorties ne peut pas être dans le cache brut."));
    }
    let key: [u8; 32] = rand::random();
    let safety = if cfg.safety_net.action == "report" { SafetyAction::Report } else { SafetyAction::Replace };
    let layout = if cfg.output.layout == "faithful" { Layout::Faithful } else { Layout::Compact };
    let mut engines: HashMap<String, Arc<Engine>> = HashMap::new();
    let keep_mapping = cfg.pseudonyms.mapping_table;
    let (download_slots, processing_slots) = (cfg.transfer.downloads(), cfg.transfer.processing());

    // Une sortie par fichier : app, cluster, type et jour. Rien n'est regroupé.
    let mut work: Vec<Work> = Vec::new();
    for (i, (pf, _, _)) in files.iter().enumerate() {
        let label = format!("{}/{}/{}", pf.app, pf.cluster, pf.kind);
        let Some(template) = pf.template.clone().filter(|_| pf.problem.is_none()) else {
            skipped.push(format!("{} · {label} : {}", pf.day, pf.problem.clone().unwrap_or_else(|| "aucun template".into())));
            continue;
        };
        let engine = match engines.get(&template) {
            Some(e) => e.clone(),
            None => {
                let tpl = Arc::new(state.library.read().expect("verrou bibliothèque").compile(&template)?);
                let e = Arc::new(Engine::new(tpl, EngineOptions { key, safety, collect_mapping: keep_mapping })?);
                engines.insert(template.clone(), e.clone());
                e
            }
        };
        work.push(Work { file: i, label, engine, template });
    }
    let count = work.len();
    // Découpage en parties : taille visée en tokens, estimée en octets.
    let part_bytes = (cfg.output.chunk_tokens > 0).then(|| cfg.output.chunk_tokens * BYTES_PER_TOKEN);

    // Les deux étapes tournent en même temps, chacune sur plusieurs fichiers : chaque fichier
    // arrivé entre dans la file de traitement, sans attendre les autres.
    let stop = token.child_token();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AppResult<(usize, PathBuf)>>();

    let downloads = async {
        let tx = tx;
        let (files, work, cache, session, server, stop) = (&files, &work, &cache, &session, &server, &stop);
        let fetch = move |k: usize| async move {
            if stop.is_cancelled() {
                return Err(AppError::new("cancelled", "Run annulé."));
            }
            let w = &work[k];
            let (pf, rf, day) = &files[w.file];
            let step = format!("{} · {}", w.label, pf.day);
            let raw_path = cache.path_for(&server.id, *day, &pf.app, &pf.cluster, rf.kind);
            let event = |done: u64, total: u64, finished: bool| RunProgress {
                run_id: run_id.to_string(),
                file_index: k as u32,
                file_count: count as u32,
                label: step.clone(),
                phase: "download".into(),
                bytes_done: done,
                bytes_total: total,
                processed_bytes: 0,
                entries_in: 0,
                dropped: 0,
                modified: 0,
                finished,
            };
            let bytes = if cache.lookup(&server.id, *day, &pf.app, &pf.cluster, rf).is_valid() {
                rf.size
            } else {
                let throttle = Throttle::new();
                // Un `.log` est compressé à la volée : on reçoit moins d'octets que sa taille,
                // le total n'est donc pas connaissable.
                let total_bytes = if rf.compressed { rf.size } else { 0 };
                let on_bytes = |received: u64| {
                    if throttle.ready() {
                        let _ = event(received, total_bytes, false).emit(app);
                    }
                };
                let sudo = state.sudo_password(&server.id);
                let outcome = session.download(rf, &raw_path, sudo.as_ref(), on_bytes, stop.clone()).await?;
                cache.write_meta(&server.id, *day, &pf.app, &pf.cluster, rf, true)?;
                outcome.bytes
            };
            // Fichier disponible (téléchargé ou déjà en cache) : étape à 100 %.
            let bytes = bytes.max(1);
            let _ = event(bytes, bytes, true).emit(app);
            Ok((k, raw_path))
        };
        let mut fetched = futures_util::stream::iter(0..count).map(fetch).buffer_unordered(download_slots);
        let mut failed = false;
        while let Some(result) = fetched.next().await {
            // Après un échec, on laisse les téléchargements en cours s'arrêter proprement.
            if failed {
                continue;
            }
            failed = result.is_err();
            if tx.send(result).is_err() || failed {
                failed = true;
                stop.cancel();
            }
        }
    };

    let disk_full = Arc::new(AtomicBool::new(false));
    let processing = async {
        let internal = |e: tokio::task::JoinError| AppError::new("internal", format!("traitement interrompu : {e}"));
        let mut running = FuturesUnordered::new();
        // Sorties terminées, avec leur rang dans la liste de travail.
        let mut finished: Vec<(usize, FileResult)> = Vec::new();
        let outcome: AppResult<()> = async {
            let mut receiving = true;
            loop {
                tokio::select! {
                    message = rx.recv(), if receiving && running.len() < processing_slots => {
                        let Some(message) = message else {
                            receiving = false;
                            continue;
                        };
                        let (k, raw_path) = message?;
                        if token.is_cancelled() {
                            return Err(AppError::new("cancelled", "Run annulé."));
                        }
                        ensure_disk_space(&out_root)?;
                        let w = &work[k];
                        let pf = &files[w.file].0;
                        let step = format!("{} · {}", w.label, pf.day);
                        let out_path = out_root.join(&pf.app).join(&pf.cluster).join(format!("{}.{}.log", pf.kind, pf.day));
                        let header = cfg.output.header.then(|| {
                            format!(
                                "# logs anonymisés · app={} · cluster={} · type={} · jour={} · template={}@{}",
                                pf.app,
                                pf.cluster,
                                pf.kind,
                                pf.day,
                                w.engine.template().id,
                                w.engine.template().version
                            )
                        });
                        let _ = progress(k, count, &step, "anonymize", 0, 0, None).emit(app);
                        let job = {
                            let (engine, flag, app, run_id, out_root, disk_full, raw) =
                                (w.engine.clone(), flag.clone(), app.clone(), run_id.to_string(), out_root.clone(), disk_full.clone(), raw_path.clone());
                            move || -> AppResult<(PartWriter, Stats)> {
                                let mut writer = PartWriter::new(out_path, part_bytes);
                                let run = (|| -> AppResult<Stats> {
                                    writer.set_context(header)?;
                                    let input = open_input_counted(&raw)?;
                                    let (read, size) = (input.read.clone(), input.size);
                                    let opts = RunOptions { layout, ..Default::default() };
                                    let mut ticks = 0u32;
                                    let stats = run_to_sink(input.reader, &engine, &mut writer, &opts, &flag, &mut |p| {
                                        // Garde-fou : on arrête avant que le disque ne soit plein.
                                        ticks += 1;
                                        if ticks.is_multiple_of(16) && free_space(&out_root).is_some_and(|free| free < MIN_FREE_BYTES) {
                                            disk_full.store(true, Ordering::Relaxed);
                                            flag.store(true, Ordering::Relaxed);
                                        }
                                        let _ = RunProgress {
                                            run_id: run_id.clone(),
                                            file_index: k as u32,
                                            file_count: count as u32,
                                            label: step.clone(),
                                            phase: "anonymize".into(),
                                            bytes_done: read.load(Ordering::Relaxed).min(size),
                                            bytes_total: size,
                                            processed_bytes: p.bytes_in,
                                            entries_in: p.entries_in,
                                            dropped: p.dropped,
                                            modified: p.modified,
                                            finished: false,
                                        }
                                        .emit(&app);
                                    })?;
                                    Ok(stats)
                                })();
                                match run {
                                    Ok(stats) => Ok((writer, stats)),
                                    Err(e) => {
                                        // Jamais de sortie partielle laissée sur le disque.
                                        writer.abort();
                                        Err(e)
                                    }
                                }
                            }
                        };
                        let handle = tokio::task::spawn_blocking(job);
                        running.push(async move { (k, raw_path, handle.await) });
                    }
                    Some((k, raw_path, joined)) = running.next() => {
                        let (writer, stats) = match joined.map_err(internal)? {
                            Ok(done) => done,
                            // Le garde-fou arrête tous les traitements : c'est lui qu'on signale.
                            Err(_) if disk_full.load(Ordering::Relaxed) => return Err(disk_full_error()),
                            Err(e) => return Err(e),
                        };
                        let w = &work[k];
                        let pf = &files[w.file].0;
                        let done = logano_core::Progress {
                            entries_in: stats.entries_in,
                            entries_out: stats.entries_out,
                            dropped: stats.dropped,
                            modified: stats.modified,
                            bytes_in: stats.bytes_in,
                            bytes_out: stats.bytes_out,
                        };
                        let mut event = progress(k, count, &format!("{} · {}", w.label, pf.day), "anonymize", 1, 1, Some(&done));
                        event.finished = true;
                        let _ = event.emit(app);

                        let quarantined = safety == SafetyAction::Report && stats.safety_total() > 0;
                        let output_id = format!("{run_id}/{}/{}", w.label, pf.day);
                        let paths = writer.paths().to_vec();
                        finished.push((k, file_result(&output_id, pf, vec![pf.day.clone()], &w.engine, &stats, &paths, quarantined)));
                        state.outputs.lock().expect("verrou sorties").insert(
                            output_id,
                            OutputInfo {
                                paths,
                                raw_paths: vec![raw_path],
                                days: vec![pf.day.clone()],
                                app: pf.app.clone(),
                                kind: pf.kind.clone(),
                                template: w.template.clone(),
                                key,
                                quarantined,
                                file_name: format!("{}-{}-{}-{}.log", pf.app, pf.cluster, pf.kind, pf.day),
                            },
                        );
                    }
                    else => break,
                }
            }
            Ok(())
        }
        .await;
        if outcome.is_err() {
            // Arrête les téléchargements et les traitements en cours. Un traitement qui
            // échoue supprime lui-même sa sortie ; celui qui finit quand même est écarté.
            stop.cancel();
            flag.store(true, Ordering::Relaxed);
            while let Some((_, _, joined)) = running.next().await {
                if let Ok(Ok((mut writer, _))) = joined {
                    writer.abort();
                }
            }
        }
        // Résultats par application, cluster et type, puis par jour.
        finished.sort_by(|(a, _), (b, _)| {
            let key = |k: usize| (work[k].label.as_str(), files[work[k].file].0.day.as_str());
            key(*a).cmp(&key(*b))
        });
        results.extend(finished.into_iter().map(|(_, r)| r));
        outcome
    };

    let ((), processed) = tokio::join!(downloads, processing);
    processed?;

    // Table de correspondance du run, chiffrée. Un échec (trousseau indisponible) ne fait pas
    // échouer le run : il est signalé, et les sorties restent valables.
    if keep_mapping {
        let mut pairs: Vec<(String, String)> = engines.values().flat_map(|e| e.mapping()).collect();
        pairs.sort();
        pairs.dedup();
        if !pairs.is_empty() {
            match crate::mapping::keychain_key().and_then(|k| crate::mapping::save(&state.dirs.mappings(), &k, run_id, &pairs)) {
                Ok(n) => *mapping_tokens = n,
                Err(e) => skipped.push(format!("Table de correspondance non enregistrée : {}", e.message)),
            }
        }
    }
    Ok(())
}

/// Un fichier à traiter : sa place dans la liste des fichiers, et de quoi écrire sa sortie.
struct Work {
    file: usize,
    /// `app/cluster/type`.
    label: String,
    engine: Arc<Engine>,
    template: String,
}

/// En dessous de cet espace libre sur le volume des sorties, un run s'arrête.
pub const MIN_FREE_BYTES: u64 = 2 << 30;

/// Espace libre sur le volume qui contient `path` (ou son premier parent existant).
pub fn free_space(path: &Path) -> Option<u64> {
    let mut p = path;
    loop {
        if p.exists() {
            return fs4::available_space(p).ok();
        }
        p = p.parent()?;
    }
}

fn disk_full_error() -> AppError {
    AppError::new(
        "disk_full",
        "Il reste moins de 2 Go libres sur le disque des sorties : le run est arrêté et ses sorties en cours supprimées. Réduis la période, ajoute des filtres ou libère de la place.",
    )
}

fn ensure_disk_space(out_root: &Path) -> AppResult<()> {
    match free_space(out_root) {
        Some(free) if free < MIN_FREE_BYTES => Err(disk_full_error()),
        _ => Ok(()),
    }
}

/// Exécute un run et émet `RunDone` à la fin, quelle que soit l'issue.
pub async fn execute_run(app: AppHandle, run_id: String, req: PlanRequest, token: CancellationToken, flag: Arc<AtomicBool>) {
    let state = app.state::<AppState>();
    let started_at = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let mut output = RunOutput::default();
    let result = run_inner(&app, &state, &run_id, &req, &token, &flag, &mut output).await;
    state.runs.lock().expect("verrou runs").remove(&run_id);
    // Le cache repasse sous sa taille maximale ; les fichiers de ce run sont gardés, pour
    // pouvoir le rejouer sans retélécharger.
    let max = state.config().cache.max_size;
    if max > 0 {
        let prefix = format!("{run_id}/");
        let keep: Vec<PathBuf> =
            state.outputs.lock().expect("verrou sorties").iter().filter(|(id, _)| id.starts_with(&prefix)).flat_map(|(_, o)| o.raw_paths.clone()).collect();
        let _ = RawCache::new(&state.dirs.raw_cache).evict_to(max, &keep);
    }
    let (cancelled, error) = match result {
        Ok(()) => (false, None),
        Err(e) if e.code == "cancelled" => (true, None),
        Err(e) => (false, Some(e)),
    };
    let done = RunDone { run_id, cancelled, error, files: output.files, skipped: output.skipped, mapping_tokens: output.mapping_tokens };
    let _ = crate::history::record(&state.dirs.history(), &started_at, &req, &done);
    let _ = done.emit(&app);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_are_sorted_deduplicated_and_validated() {
        let days = |list: &[&str]| parse_days(&list.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let parsed = days(&["2026-11-09", "2026-11-07", "2026-11-09", "2026-11-08"]).unwrap();
        assert_eq!(parsed.iter().map(|d| d.to_string()).collect::<Vec<_>>(), vec!["2026-11-07", "2026-11-08", "2026-11-09"]);
        assert_eq!(days(&[]).unwrap_err().code, "invalid_day");
        assert_eq!(days(&["09/11/2026"]).unwrap_err().code, "invalid_day");
        assert_eq!(days(&["2026-02-30"]).unwrap_err().code, "invalid_day");
    }
}

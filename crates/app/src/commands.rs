//! Commandes exposées à l'interface.

use crate::config::{AppConfig, Association};
use crate::dto::*;
use crate::error::{AppError, AppResult};
use crate::runner::{collect_files, execute_run, free_space, parse_days};
use crate::state::{AppState, RunHandle};
use logano_core::engine::SafetyAction;
use logano_core::format::make_format;
use logano_core::pipeline::{open_input, sandbox};
use logano_core::profile::ProfileOptions;
use logano_core::template::testing::run_tests;
use logano_core::{Engine, EngineOptions, SandboxEntry, Stats};
use logano_remote::{
    AuthConfig, BastionConfig, CancellationToken, HostKeyPolicy, JumpMode, RawCache, RemoteError, SecretString, ServerConfig,
    DEFAULT_IDENTITY_FILE, DEFAULT_PATH_PATTERN,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

const SANDBOX_MAX_INPUT: usize = 2 << 20;
const SANDBOX_MAX_ENTRIES: usize = 500;
const PREVIEW_BYTES: u64 = 512 << 10;
const CLIPBOARD_MAX: u64 = 8 << 20;

fn bastion_to_dto(b: &BastionConfig) -> BastionDto {
    let (auth, identity_file) = match &b.auth {
        AuthConfig::Key { identity_file } => ("key", identity_file.clone()),
        AuthConfig::Agent => ("agent", DEFAULT_IDENTITY_FILE.to_string()),
    };
    BastionDto {
        host: b.host.clone(),
        user: b.user.clone(),
        port: b.port,
        auth: auth.to_string(),
        identity_file,
        mode: match b.mode {
            JumpMode::Nc => "nc",
            JumpMode::DirectTcpip => "direct_tcpip",
        }
        .to_string(),
        host_key_policy: match b.host_key_policy {
            HostKeyPolicy::Insecure => "insecure",
            HostKeyPolicy::Tofu => "tofu",
        }
        .to_string(),
    }
}

fn apply_bastion(dto: &BastionDto, existing: Option<BastionConfig>) -> AppResult<BastionConfig> {
    if dto.host.trim().is_empty() || dto.user.trim().is_empty() {
        return Err(AppError::new("config_invalid", "Bastion : l'hôte et l'utilisateur sont requis."));
    }
    let mut b = existing.unwrap_or_else(|| BastionConfig::new(dto.host.trim(), dto.user.trim()));
    b.host = dto.host.trim().to_string();
    b.user = dto.user.trim().to_string();
    b.port = if dto.port == 0 { 22 } else { dto.port };
    b.auth = match dto.auth.as_str() {
        "agent" => AuthConfig::Agent,
        _ => AuthConfig::Key {
            identity_file: if dto.identity_file.trim().is_empty() { DEFAULT_IDENTITY_FILE.to_string() } else { dto.identity_file.trim().to_string() },
        },
    };
    b.mode = if dto.mode == "direct_tcpip" { JumpMode::DirectTcpip } else { JumpMode::Nc };
    b.host_key_policy = if dto.host_key_policy == "tofu" { HostKeyPolicy::Tofu } else { HostKeyPolicy::Insecure };
    Ok(b)
}

fn server_to_dto(s: &ServerConfig) -> ServerDto {
    ServerDto { id: s.id.clone(), name: s.name.clone(), host: s.host.clone(), path_pattern: s.path_pattern.clone() }
}

fn config_to_dto(state: &AppState, cfg: &AppConfig) -> ConfigDto {
    ConfigDto {
        bastion: cfg.bastion.as_ref().map(bastion_to_dto),
        servers: cfg.servers.iter().map(server_to_dto).collect(),
        associations: cfg
            .associations
            .iter()
            .map(|a| AssociationDto { app: a.app.clone(), log_kind: a.log_kind.clone(), template: a.template.clone() })
            .collect(),
        output_dir: cfg.output.dir.clone(),
        output_dir_effective: state.dirs.output_root(cfg).display().to_string(),
        layout: cfg.output.layout.clone(),
        header: cfg.output.header,
        chunk_tokens: cfg.output.chunk_tokens.min(u32::MAX as u64) as u32,
        confirm_above_mb: (cfg.transfer.confirm_above >> 20) as u32,
        parallel_downloads: cfg.transfer.downloads() as u32,
        parallel_processing: cfg.transfer.processing() as u32,
        cache_max_gb: (cfg.cache.max_size >> 30) as u32,
        mapping_table: cfg.pseudonyms.mapping_table,
        safety_action: cfg.safety_net.action.clone(),
    }
}

#[tauri::command]
#[specta::specta]
pub fn get_config(state: State<'_, AppState>) -> ConfigDto {
    config_to_dto(&state, &state.config())
}

/// Enregistre la config. Les champs que l'interface ne montre pas (utilisateur ou bastion
/// propre à un serveur) sont conservés.
#[tauri::command]
#[specta::specta]
pub fn save_config(state: State<'_, AppState>, config: ConfigDto) -> AppResult<ConfigDto> {
    let mut cfg = state.config();
    cfg.bastion = match &config.bastion {
        Some(dto) => Some(apply_bastion(dto, cfg.bastion.take())?),
        None => None,
    };
    let mut servers = Vec::with_capacity(config.servers.len());
    for dto in &config.servers {
        let id = dto.id.trim();
        let valid = !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
        if !valid || dto.host.trim().is_empty() {
            return Err(AppError::new("config_invalid", format!("Serveur « {} » : identifiant en [A-Za-z0-9_-] et hôte requis.", dto.id)));
        }
        if servers.iter().any(|s: &ServerConfig| s.id == id) {
            return Err(AppError::new("config_invalid", format!("Deux serveurs portent l'identifiant « {id} ».")));
        }
        let mut s = cfg.servers.iter().find(|s| s.id == id).cloned().unwrap_or_else(|| ServerConfig::new(id, dto.name.trim(), dto.host.trim()));
        s.name = if dto.name.trim().is_empty() { id.to_string() } else { dto.name.trim().to_string() };
        s.host = dto.host.trim().to_string();
        s.path_pattern = if dto.path_pattern.trim().is_empty() { DEFAULT_PATH_PATTERN.to_string() } else { dto.path_pattern.trim().to_string() };
        servers.push(s);
    }
    cfg.servers = servers;
    cfg.associations =
        config.associations.iter().map(|a| Association { app: a.app.clone(), log_kind: a.log_kind.clone(), template: a.template.clone() }).collect();
    cfg.output.dir = config.output_dir.trim().to_string();
    cfg.output.layout = if config.layout == "faithful" { "faithful".into() } else { "compact".into() };
    cfg.output.header = config.header;
    cfg.output.chunk_tokens = config.chunk_tokens as u64;
    cfg.transfer.confirm_above = (config.confirm_above_mb as u64) << 20;
    cfg.transfer.parallel_downloads = config.parallel_downloads.clamp(1, crate::config::MAX_PARALLEL);
    cfg.transfer.parallel_processing = config.parallel_processing.clamp(1, crate::config::MAX_PARALLEL);
    cfg.cache.max_size = (config.cache_max_gb as u64) << 30;
    cfg.pseudonyms.mapping_table = config.mapping_table;
    cfg.safety_net.action = if config.safety_action == "report" { "report".into() } else { "replace".into() };
    if state.dirs.output_root(&cfg).starts_with(&state.dirs.raw_cache) {
        return Err(AppError::new("config_invalid", "Le dossier des sorties ne peut pas être dans le cache brut."));
    }
    cfg.save(&state.dirs.config_path())?;
    *state.config.write().expect("verrou config") = cfg.clone();
    Ok(config_to_dto(&state, &cfg))
}

/// Propose un bastion et des serveurs depuis `~/.ssh/config`, `~/.zshrc` et l'historique du shell
/// (seulement ses commandes `ssh … syslogserver…`). Rien n'est enregistré.
#[tauri::command]
#[specta::specta]
pub fn import_ssh() -> ImportDto {
    // L'historique de zsh n'est pas toujours de l'UTF-8 valide : lecture tolérante.
    let read = |p: &str| std::fs::read(logano_remote::expand_tilde(p)).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let history = ["~/.zsh_history", "~/.bash_history"].map(read).join("\n");
    let proposal = logano_remote::import_ssh_config(&read("~/.ssh/config"), &read("~/.zshrc"), &history);
    ImportDto { bastion: proposal.bastion.as_ref().map(bastion_to_dto), servers: proposal.servers.iter().map(server_to_dto).collect() }
}

#[tauri::command]
#[specta::specta]
pub fn list_templates(state: State<'_, AppState>) -> Vec<TemplateInfo> {
    let lib = state.library.read().expect("verrou bibliothèque");
    lib.ids()
        .filter_map(|id| {
            let file = lib.get(id)?;
            let meta = &file.template;
            let (available, problem, warnings, rules) = match lib.compile(id) {
                Ok(t) => match make_format(t.format) {
                    Ok(_) => (true, None, t.warnings.clone(), t.rules.len()),
                    Err(e) => (false, Some(e.to_string()), t.warnings.clone(), t.rules.len()),
                },
                Err(e) => (false, Some(e.to_string()), Vec::new(), 0),
            };
            Some(TemplateInfo {
                id: id.to_string(),
                name: meta.name.clone(),
                version: meta.version.clone(),
                description: meta.description.clone().unwrap_or_default(),
                log_kind: meta.log_kind.clone(),
                format: meta.format.clone(),
                builtin: lib.is_builtin(id),
                is_abstract: meta.is_abstract,
                available,
                problem,
                warnings,
                suggested_apps: meta.suggested_apps.clone(),
                tests: file.tests.len() as u32,
                rules: rules as u32,
            })
        })
        .collect()
}

#[tauri::command]
#[specta::specta]
pub fn run_template_tests(state: State<'_, AppState>, template_id: String) -> AppResult<Vec<TestOutcomeDto>> {
    let lib = state.library.read().expect("verrou bibliothèque");
    Ok(run_tests(&lib, &template_id)?
        .into_iter()
        .map(|o| TestOutcomeDto { name: o.name, passed: o.passed, failures: o.failures, output: o.output })
        .collect())
}

/// Texte TOML d'un template de la bibliothèque.
#[tauri::command]
#[specta::specta]
pub fn template_source(state: State<'_, AppState>, template_id: String) -> AppResult<TemplateSource> {
    let lib = state.library.read().expect("verrou bibliothèque");
    let toml = lib.source(&template_id).ok_or_else(|| AppError::new("template_not_found", format!("Template « {template_id} » introuvable.")))?;
    Ok(TemplateSource { id: template_id.clone(), toml: toml.to_string(), builtin: lib.is_builtin(&template_id) })
}

fn check_template(state: &AppState, toml: &str) -> TemplateCheck {
    let current = state.library.read().expect("verrou bibliothèque").clone();
    // On valide dans une copie de la bibliothèque : rien n'est enregistré.
    let mut lib = current.clone();
    match lib.add_str(toml) {
        Ok(id) => check_in_library(&current, &lib, &id),
        Err(e) => TemplateCheck { ok: false, id: None, error: Some(e.to_string()), warnings: Vec::new(), tests: Vec::new(), weakens: Vec::new(), exists: false, builtin: false },
    }
}

/// Valide le template `id` de `lib` (compilation, tests, ce qui affaiblit la protection).
/// `current` est la bibliothèque en place, pour dire s'il existe déjà.
pub(crate) fn check_in_library(current: &logano_core::Library, lib: &logano_core::Library, id: &str) -> TemplateCheck {
    let id = id.to_string();
    let mut check = TemplateCheck { ok: false, id: None, error: None, warnings: Vec::new(), tests: Vec::new(), weakens: Vec::new(), exists: false, builtin: false };
    check.exists = current.get(&id).is_some();
    check.builtin = current.is_builtin(&id);
    check.id = Some(id.clone());
    let compiled = match lib.compile(&id) {
        Ok(c) => c,
        Err(e) => {
            check.error = Some(e.to_string());
            return check;
        }
    };
    check.warnings = compiled.warnings.clone();
    if let Some(file) = lib.get(&id) {
        let a = &file.allowlist;
        for (what, list) in [("domaines", &a.domains), ("plages d'IP", &a.cidrs), ("emails", &a.emails), ("valeurs", &a.values)] {
            if !list.is_empty() {
                check.weakens.push(format!("Allowlist, {what} jamais remplacés : {}", list.join(", ")));
            }
        }
        for r in &file.rules {
            if r.id.contains(':') && r.enabled == Some(false) {
                check.weakens.push(format!("Règle héritée désactivée : {}", r.id));
            }
            if r.strategy.as_deref() == Some("keep") {
                check.weakens.push(format!("Valeurs gardées en clair (règle {}) : {}", r.id, r.keys.clone().unwrap_or_default().join(", ")));
            }
        }
    }
    match run_tests(lib, &id) {
        Ok(outcomes) => {
            check.ok = outcomes.iter().all(|o| o.passed);
            if !check.ok {
                check.error = Some("Des tests embarqués échouent.".to_string());
            }
            check.tests = outcomes.into_iter().map(|o| TestOutcomeDto { name: o.name, passed: o.passed, failures: o.failures, output: o.output }).collect();
        }
        // Format pas encore exécutable : le template est valide, ses tests ne peuvent pas tourner.
        Err(e) => {
            check.ok = true;
            check.warnings.push(e.to_string());
        }
    }
    check
}

/// Valide un texte de template sans l'enregistrer : schéma, héritage, compilation, tests.
#[tauri::command]
#[specta::specta]
pub fn template_check(state: State<'_, AppState>, toml: String) -> TemplateCheck {
    check_template(&state, &toml)
}

/// Enregistre un template de l'utilisateur. Refusé s'il n'est pas valide, si ses tests
/// échouent, ou s'il porte l'identifiant d'un template fourni avec l'app.
#[tauri::command]
#[specta::specta]
pub fn template_save(state: State<'_, AppState>, toml: String) -> AppResult<String> {
    let check = check_template(&state, &toml);
    let id = match (&check.id, check.ok) {
        (Some(id), true) => id.clone(),
        _ => return Err(AppError::new("template_invalid", check.error.unwrap_or_else(|| "Template invalide.".into()))),
    };
    if check.builtin {
        return Err(AppError::new("template_invalid", format!("« {id} » est fourni avec l'app : enregistre ta version sous un autre identifiant.")));
    }
    crate::local::write_validated(&state, &id, &crate::local::user_path(&state, &id), &toml)?;
    Ok(id)
}

#[tauri::command]
#[specta::specta]
pub fn template_delete(state: State<'_, AppState>, template_id: String) -> AppResult<()> {
    crate::local::delete(&state, &template_id)
}

/// Importe des templates en lot : des `.toml` et des `.zip` choisis (`folder = false`), ou
/// tous les `.toml` d'un dossier. Chaque template est validé avant d'être enregistré ; le
/// rapport dit ce qui est entré, remplacé ou refusé. `None` si le dialogue est annulé.
#[tauri::command]
#[specta::specta]
pub async fn templates_import(app: AppHandle, folder: bool) -> AppResult<Option<ImportReport>> {
    tokio::task::spawn_blocking(move || -> AppResult<Option<ImportReport>> {
        let invalid = |e| AppError::new("local_io", format!("chemin invalide : {e}"));
        let paths = if folder {
            let Some(dir) = app.dialog().file().blocking_pick_folder() else { return Ok(None) };
            vec![dir.into_path().map_err(invalid)?]
        } else {
            let Some(files) = app.dialog().file().add_filter("Templates (.toml, .zip)", &["toml", "zip"]).blocking_pick_files() else { return Ok(None) };
            files.into_iter().map(|f| f.into_path().map_err(invalid)).collect::<AppResult<Vec<_>>>()?
        };
        let state = tauri::Manager::state::<AppState>(&app);
        crate::import::import(&state, crate::import::collect(&paths)?).map(Some)
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))?
}

/// Exporte le `.toml` d'un template vers un fichier choisi. `None` si le dialogue est annulé.
#[tauri::command]
#[specta::specta]
pub async fn template_export(app: AppHandle, state: State<'_, AppState>, template_id: String) -> AppResult<Option<String>> {
    let toml = template_source(state, template_id.clone())?.toml;
    tokio::task::spawn_blocking(move || -> AppResult<Option<String>> {
        let name = format!("{}.toml", template_id.replace('/', "-"));
        let Some(dest) = app.dialog().file().set_file_name(&name).blocking_save_file() else { return Ok(None) };
        let dest = dest.into_path().map_err(|e| AppError::new("local_io", format!("destination invalide : {e}")))?;
        std::fs::write(&dest, toml)?;
        Ok(Some(dest.display().to_string()))
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))?
}

fn sandbox_result(entries: Vec<SandboxEntry>, stats: &Stats, warnings: Vec<String>, template: String) -> SandboxResult {
    let seg = |s: logano_core::Segment| SegmentDto { text: s.text, rule: s.rule, safety: s.safety };
    SandboxResult {
        entries: entries
            .into_iter()
            .map(|e| SandboxEntryDto {
                source: e.source,
                line_no: e.line_no,
                kind: e.kind,
                dropped_by: e.dropped_by,
                raw: e.raw.into_iter().map(seg).collect(),
                out: e.out.into_iter().map(seg).collect(),
            })
            .collect(),
        entries_in: stats.entries_in,
        dropped: stats.dropped,
        modified: stats.modified,
        safety_total: stats.safety_total(),
        warnings,
        template,
    }
}

/// Bac à sable : anonymise des lignes collées et rend le brut et l'anonymisé côte à côte.
#[tauri::command]
#[specta::specta]
pub async fn sandbox_run(state: State<'_, AppState>, template_id: String, input: String) -> AppResult<SandboxResult> {
    if input.len() > SANDBOX_MAX_INPUT {
        return Err(AppError::new("too_large", "Le bac à sable accepte 2 Mo au plus."));
    }
    let tpl = Arc::new(state.library.read().expect("verrou bibliothèque").compile(&template_id)?);
    let warnings = tpl.warnings.clone();
    let used = format!("{}@{}", tpl.id, tpl.version);
    let engine = Engine::new(tpl, EngineOptions::with_key(state.sandbox_key))?;
    let (entries, stats) = tokio::task::spawn_blocking(move || sandbox(&engine, input.as_bytes(), SANDBOX_MAX_ENTRIES))
        .await
        .map_err(|e| AppError::new("internal", e.to_string()))?;
    Ok(sandbox_result(entries, &stats, warnings, used))
}

/// Apps et clusters présents sur un serveur pour les jours demandés (union des jours).
/// Un jour sans dossier est signalé, sans échec, tant qu'un autre jour en a un.
#[tauri::command]
#[specta::specta]
pub async fn discover(state: State<'_, AppState>, server_id: String, days: Vec<String>) -> AppResult<DiscoverResult> {
    let days = parse_days(&days)?;
    let (_, session) = state.session(&server_id).await?;
    let mut apps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut missing_days = Vec::new();
    let mut first_missing = None;
    for day in &days {
        match session.discover_apps(*day).await {
            Ok(list) => {
                for a in list {
                    apps.entry(a.name).or_default().extend(a.clusters);
                }
            }
            Err(e @ RemoteError::DayNotFound { .. }) => {
                missing_days.push(day.to_string());
                first_missing.get_or_insert(e);
            }
            Err(e) => return Err(e.into()),
        }
    }
    if apps.is_empty() {
        if let Some(e) = first_missing {
            return Err(e.into());
        }
    }
    Ok(DiscoverResult {
        apps: apps.into_iter().map(|(name, clusters)| AppInfoDto { name, clusters: clusters.into_iter().collect() }).collect(),
        missing_days,
    })
}

/// Fichiers qu'un run traiterait, avec leur taille, avant tout téléchargement.
/// Rend aussi les fichiers lisibles (`sudo chmod +r`).
#[tauri::command]
#[specta::specta]
pub async fn plan_run(state: State<'_, AppState>, request: PlanRequest) -> AppResult<Plan> {
    let (server, session) = state.session(&request.server_id).await?;
    let cache = RawCache::new(&state.dirs.raw_cache);
    let (files, missing) = collect_files(&state, &session, &cache, &request).await?;
    let to_read: Vec<&str> = files.iter().filter(|(pf, _, _)| !pf.cached && pf.problem.is_none()).map(|(_, rf, _)| rf.path.as_str()).collect();
    if !to_read.is_empty() {
        session.ensure_readable(&to_read, state.sudo_password(&server.id).as_ref()).await?;
    }
    let usable = |pf: &PlanFile| pf.problem.is_none();
    let total_bytes = files.iter().filter(|(pf, _, _)| usable(pf)).map(|(pf, _, _)| pf.size).sum();
    let download_bytes: u64 = files.iter().filter(|(pf, _, _)| usable(pf) && !pf.cached).map(|(pf, _, _)| pf.size).sum();
    // Estimation haute : un gzip de logs se décompresse d'un facteur 17 environ, et la
    // sortie pèse au plus autant que le brut (les filtres ne peuvent que la réduire).
    let estimated_output_bytes: u64 = files.iter().filter(|(pf, _, _)| usable(pf)).map(|(pf, _, _)| if pf.compressed { pf.size * 17 } else { pf.size }).sum();
    let cfg = state.config();
    let output_free_bytes = free_space(&state.dirs.output_root(&cfg)).unwrap_or(u64::MAX);
    let cache_free_bytes = free_space(&state.dirs.raw_cache).unwrap_or(u64::MAX);
    // Cache et sorties sont en général sur le même volume : on compte les deux ensemble.
    let needed = download_bytes + estimated_output_bytes;
    let free = output_free_bytes.min(cache_free_bytes);
    let gb = |n: u64| format!("{:.1} Go", n as f64 / (1u64 << 30) as f64);
    let disk_warning = (needed > free / 10 * 9).then(|| {
        format!(
            "Ce run peut écrire jusqu'à {} ({} à télécharger, {} de sortie avant filtres) pour {} libres. Il s'arrêtera de lui-même s'il reste moins de 2 Go.",
            gb(needed),
            gb(download_bytes),
            gb(estimated_output_bytes),
            gb(free)
        )
    });
    Ok(Plan {
        estimated_output_bytes,
        output_free_bytes,
        cache_free_bytes,
        disk_warning,
        needs_confirmation: download_bytes > state.config().transfer.confirm_above,
        files: files.into_iter().map(|(pf, _, _)| pf).collect(),
        total_bytes,
        download_bytes,
        missing,
    })
}

/// Lance un run en arrière-plan. La progression arrive par `RunProgress`, la fin par `RunDone`.
#[tauri::command]
#[specta::specta]
pub fn start_run(app: AppHandle, state: State<'_, AppState>, request: PlanRequest) -> AppResult<String> {
    let days = parse_days(&request.days)?;
    let span = match (days.first(), days.last()) {
        (Some(a), Some(b)) if a != b => format!("{a}_{b}"),
        (Some(a), _) => a.to_string(),
        _ => String::new(),
    };
    let run_id = format!("{}-{}-{span}", chrono::Local::now().format("%Y%m%d-%H%M%S"), request.server_id);
    let token = CancellationToken::new();
    let flag = Arc::new(AtomicBool::new(false));
    state.runs.lock().expect("verrou runs").insert(run_id.clone(), RunHandle { token: token.clone(), flag: flag.clone() });
    tauri::async_runtime::spawn(execute_run(app, run_id.clone(), request, token, flag));
    Ok(run_id)
}

#[tauri::command]
#[specta::specta]
pub fn cancel_run(state: State<'_, AppState>, run_id: String) {
    if let Some(h) = state.runs.lock().expect("verrou runs").get(&run_id) {
        h.token.cancel();
        h.flag.store(true, Ordering::Relaxed);
    }
}

/// Mot de passe sudo d'un serveur : gardé en mémoire pour la session, jamais écrit.
#[tauri::command]
#[specta::specta]
pub fn provide_sudo_password(state: State<'_, AppState>, server_id: String, password: String) {
    state.sudo_passwords.lock().expect("verrou sudo").insert(server_id, SecretString::from(password));
}

/// Phrase de passe d'une clé SSH : gardée en mémoire pour la session, jamais écrite.
#[tauri::command]
#[specta::specta]
pub async fn provide_key_passphrase(state: State<'_, AppState>, identity_file: String, passphrase: String) -> AppResult<()> {
    let secret = SecretString::from(passphrase);
    state.key_passphrases.lock().expect("verrou phrases de passe").insert(identity_file.clone(), secret.clone());
    if let Ok(pool) = state.pool().await {
        pool.set_key_passphrase(&identity_file, Some(secret));
    }
    Ok(())
}

fn output_info(state: &AppState, output_id: &str) -> AppResult<crate::state::OutputInfo> {
    state
        .outputs
        .lock()
        .expect("verrou sorties")
        .get(output_id)
        .cloned()
        .ok_or_else(|| AppError::new("unknown_output", "Cette sortie n'existe plus : relance le run."))
}

fn refuse_quarantined(info: &crate::state::OutputInfo) -> AppResult<()> {
    if info.quarantined {
        return Err(AppError::new(
            "quarantined",
            "Cette sortie contient des données signalées par le filet de sécurité et non remplacées : elle ne peut être ni copiée ni exportée.",
        ));
    }
    Ok(())
}

fn refuse_empty(info: &crate::state::OutputInfo) -> AppResult<()> {
    if info.paths.is_empty() {
        return Err(AppError::new("empty_output", "Cette sortie est vide : toutes les entrées ont été filtrées."));
    }
    Ok(())
}

/// Vue côte à côte des premières entrées d'une sortie : brut (depuis le cache) et anonymisé.
#[tauri::command]
#[specta::specta]
pub async fn preview_output(state: State<'_, AppState>, output_id: String, limit: u32) -> AppResult<SandboxResult> {
    let info = output_info(&state, &output_id)?;
    // Avec le template courant de l'application : si son template local a changé depuis le
    // run, l'aperçu montre ce que donnerait un nouveau run.
    let tpl = Arc::new(state.library.read().expect("verrou bibliothèque").compile(&state.current_template(&info))?);
    let warnings = tpl.warnings.clone();
    let used = format!("{}@{}", tpl.id, tpl.version);
    let safety = if state.config().safety_net.action == "report" { SafetyAction::Report } else { SafetyAction::Replace };
    let engine = Engine::new(tpl, EngineOptions { key: info.key, safety, collect_mapping: false })?;
    let limit = limit.clamp(1, 2000) as usize;
    let (entries, stats) = tokio::task::spawn_blocking(move || -> AppResult<_> {
        let mut head = Vec::new();
        // Une fin de flux prématurée (gzip tronqué) n'empêche pas de montrer ce qui a été lu.
        let raw = info.raw_paths.first().ok_or_else(|| AppError::new("unknown_output", "Cette sortie n'a pas de fichier brut en cache."))?;
        let _ = open_input(raw)?.take(PREVIEW_BYTES).read_to_end(&mut head);
        if let Some(cut) = head.iter().rposition(|b| *b == b'\n') {
            head.truncate(cut + 1);
        }
        Ok(sandbox(&engine, &head, limit))
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))??;
    Ok(sandbox_result(entries, &stats, warnings, used))
}

/// Copie une partie d'une sortie anonymisée dans le presse-papier. Rend le nombre d'octets copiés.
#[tauri::command]
#[specta::specta]
pub fn copy_output(app: AppHandle, state: State<'_, AppState>, output_id: String, part: u32) -> AppResult<u64> {
    let info = output_info(&state, &output_id)?;
    refuse_quarantined(&info)?;
    refuse_empty(&info)?;
    let path = info.paths.get(part as usize).ok_or_else(|| AppError::new("unknown_output", "Cette partie n'existe pas."))?;
    let size = std::fs::metadata(path)?.len();
    if size > CLIPBOARD_MAX {
        return Err(AppError::new(
            "too_large",
            format!("{} Mo : trop volumineux pour le presse-papier (8 Mo au plus). Exporte le fichier, ou découpe la sortie en parties dans les réglages.", size >> 20),
        ));
    }
    let text = String::from_utf8_lossy(&std::fs::read(path)?).into_owned();
    app.clipboard().write_text(text).map_err(|e| AppError::new("clipboard", format!("presse-papier indisponible : {e}")))?;
    Ok(size)
}

/// Exporte une sortie anonymisée : vers un fichier choisi si elle tient en un fichier, sinon
/// toutes ses parties vers un dossier choisi. Rend le chemin, ou `None` si le dialogue est annulé.
#[tauri::command]
#[specta::specta]
pub async fn export_output(app: AppHandle, state: State<'_, AppState>, output_id: String) -> AppResult<Option<String>> {
    let info = output_info(&state, &output_id)?;
    refuse_quarantined(&info)?;
    refuse_empty(&info)?;
    let raw_cache = state.dirs.raw_cache.clone();
    tokio::task::spawn_blocking(move || -> AppResult<Option<String>> {
        let in_cache = |dest: &std::path::Path| dest.starts_with(&raw_cache).then(|| AppError::new("output_in_cache", "On n'exporte pas dans le cache brut."));
        let invalid = |e: &dyn std::fmt::Display| AppError::new("local_io", format!("destination invalide : {e}"));
        if let [single] = info.paths.as_slice() {
            let Some(dest) = app.dialog().file().set_file_name(&info.file_name).blocking_save_file() else { return Ok(None) };
            let dest = dest.into_path().map_err(|e| invalid(&e))?;
            if let Some(e) = in_cache(&dest) {
                return Err(e);
            }
            std::fs::copy(single, &dest)?;
            return Ok(Some(dest.display().to_string()));
        }
        let Some(dir) = app.dialog().file().blocking_pick_folder() else { return Ok(None) };
        let dir = dir.into_path().map_err(|e| invalid(&e))?;
        if let Some(e) = in_cache(&dir) {
            return Err(e);
        }
        for (name, part) in export_names(&info).into_iter().zip(&info.paths) {
            std::fs::copy(part, dir.join(name))?;
        }
        Ok(Some(dir.display().to_string()))
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))?
}

/// Exporte plusieurs sorties d'un coup dans un dossier choisi : tous les jours d'une
/// application. Une sortie en quarantaine bloque l'export ; les sorties vides sont ignorées.
/// Rend le dossier et le nombre de fichiers copiés.
#[tauri::command]
#[specta::specta]
pub async fn export_outputs(app: AppHandle, state: State<'_, AppState>, output_ids: Vec<String>) -> AppResult<Option<String>> {
    let infos = output_ids.iter().map(|id| output_info(&state, id)).collect::<AppResult<Vec<_>>>()?;
    for info in &infos {
        refuse_quarantined(info)?;
    }
    if infos.iter().all(|i| i.paths.is_empty()) {
        return Err(AppError::new("empty_output", "Ces sorties sont vides : toutes les entrées ont été filtrées."));
    }
    let raw_cache = state.dirs.raw_cache.clone();
    tokio::task::spawn_blocking(move || -> AppResult<Option<String>> {
        let Some(dir) = app.dialog().file().blocking_pick_folder() else { return Ok(None) };
        let dir = dir.into_path().map_err(|e| AppError::new("local_io", format!("destination invalide : {e}")))?;
        if dir.starts_with(&raw_cache) {
            return Err(AppError::new("output_in_cache", "On n'exporte pas dans le cache brut."));
        }
        for info in &infos {
            for (name, part) in export_names(info).into_iter().zip(&info.paths) {
                std::fs::copy(part, dir.join(name))?;
            }
        }
        Ok(Some(dir.display().to_string()))
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))?
}

/// Noms des fichiers d'une sortie une fois exportée : le sien, ou un par partie.
fn export_names(info: &crate::state::OutputInfo) -> Vec<String> {
    if info.paths.len() <= 1 {
        return info.paths.iter().map(|_| info.file_name.clone()).collect();
    }
    let stem = info.file_name.trim_end_matches(".log");
    (1..=info.paths.len()).map(|i| format!("{stem}.part{i:03}.log")).collect()
}

/// Profile le premier jour d'une sortie : formes d'entrées par poids et inventaire des clés.
/// Le calcul part du cache brut mais ne rend que des formes masquées et des comptes.
#[tauri::command]
#[specta::specta]
pub async fn profile_output(state: State<'_, AppState>, output_id: String) -> AppResult<ProfileDto> {
    let info = output_info(&state, &output_id)?;
    let raw = info.raw_paths.first().cloned().ok_or_else(|| AppError::new("unknown_output", "Cette sortie n'a pas de fichier brut en cache."))?;
    let tpl = Arc::new(state.library.read().expect("verrou bibliothèque").compile(&state.current_template(&info))?);
    let template = format!("{}@{}", tpl.id, tpl.version);
    let engine = Engine::new(tpl, EngineOptions::with_key(info.key))?;
    let profile = tokio::task::spawn_blocking(move || -> AppResult<_> {
        Ok(logano_core::profile::profile(open_input(&raw)?, &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {})?)
    })
    .await
    .map_err(|e| AppError::new("internal", e.to_string()))??;
    Ok(ProfileDto {
        app: info.app.clone(),
        day: info.days.first().cloned().unwrap_or_default(),
        template,
        entries: profile.entries,
        bytes: profile.bytes,
        filtered_entries: profile.filtered_entries,
        filtered_bytes: profile.filtered_bytes,
        shapes_total: profile.shapes_total,
        shapes: profile
            .shapes
            .into_iter()
            .map(|s| ShapeDto { shape: s.shape, pattern: s.pattern, count: s.count, bytes: s.bytes, level: s.level, kind: s.kind, filtered_count: s.filtered_count, filtered_by: s.filtered_by })
            .collect(),
        keys_total: profile.keys_total,
        keys: profile
            .keys
            .into_iter()
            .map(|k| KeyDto {
                path: k.path,
                count: k.count,
                replaced: k.replaced,
                distinct: k.distinct,
                distinct_capped: k.distinct_capped,
                shapes: k.shapes.into_iter().map(|(shape, count)| ValueShape { shape, count }).collect(),
            })
            .collect(),
        warning: profile.input_error.map(|e| format!("fichier tronqué ou corrompu, profilé jusqu'à l'erreur : {e}")),
    })
}

/// Ajoute un filtre ou une règle au template local d'une application (`local/<app>`), créé
/// au besoin par-dessus le template de base. Le template est validé avant d'être gardé.
#[tauri::command]
#[specta::specta]
pub fn local_template_add(state: State<'_, AppState>, addition: LocalAddition) -> AppResult<LocalTemplate> {
    crate::local::add(&state, &addition)
}

/// Tables de correspondance présentes, sans leur contenu.
#[tauri::command]
#[specta::specta]
pub fn mapping_list(state: State<'_, AppState>) -> Vec<MappingInfo> {
    crate::mapping::list(&state.dirs.mappings())
}

/// Supprime la table d'un run, ou toutes.
#[tauri::command]
#[specta::specta]
pub fn mapping_purge(state: State<'_, AppState>, run_id: Option<String>) -> AppResult<()> {
    crate::mapping::purge(&state.dirs.mappings(), run_id.as_deref())
}

/// Remet les valeurs réelles dans un texte (la réponse d'une IA), avec la table d'un run.
/// Le résultat contient des données réelles : il reste dans l'app.
#[tauri::command]
#[specta::specta]
pub fn deanonymize(state: State<'_, AppState>, run_id: String, text: String) -> AppResult<Deanonymized> {
    let table = crate::mapping::load(&state.dirs.mappings(), &crate::mapping::keychain_key()?, &run_id)?;
    Ok(crate::mapping::deanonymize(&text, &table))
}

/// Runs passés, du plus récent au plus ancien.
#[tauri::command]
#[specta::specta]
pub fn history_list(state: State<'_, AppState>) -> Vec<HistoryEntry> {
    crate::history::load(&state.dirs.history())
}

#[tauri::command]
#[specta::specta]
pub fn history_clear(state: State<'_, AppState>) -> AppResult<()> {
    crate::history::clear(&state.dirs.history())
}

#[tauri::command]
#[specta::specta]
pub fn cache_info(state: State<'_, AppState>) -> AppResult<CacheInfo> {
    let cache = RawCache::new(&state.dirs.raw_cache);
    let bytes = if state.dirs.raw_cache.exists() { cache.size()? } else { 0 };
    Ok(CacheInfo { path: state.dirs.raw_cache.display().to_string(), bytes })
}

/// Vide le cache brut. Refusé pendant un run.
#[tauri::command]
#[specta::specta]
pub fn cache_purge(state: State<'_, AppState>) -> AppResult<CacheInfo> {
    if !state.runs.lock().expect("verrou runs").is_empty() {
        return Err(AppError::new("busy", "Un run est en cours : attends sa fin ou annule-le avant de vider le cache."));
    }
    if state.dirs.raw_cache.exists() {
        RawCache::new(&state.dirs.raw_cache).purge()?;
    }
    cache_info(state)
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;
    use crate::config::Dirs;

    fn state(name: &str) -> (AppState, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("logano-commands-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs = Dirs { data: root.join("data"), raw_cache: root.join("cache"), default_output: root.join("out") };
        (AppState::init(dirs).unwrap(), root)
    }

    const MINE: &str = r#"
[template]
id = "equipe/demo"
name = "Démo"
version = "1.0.0"
schema_version = 1
log_kind = "erlang"
format = "elixir_syslog"
extends = ["kbrw/elixir@^1"]

[allowlist]
emails = ["*+robot@example.com"]

[[rules]]
id = "kbrw/common:phones"
enabled = false

[[rules]]
id = "order-ids"
keys = ["order_ref"]
strategy = "keep"

[[tests]]
name = "email pseudonymisé"
input = '''
h.kbrw.fr  10:00:00.000 [info]  owner jean@example.com not found
'''
expect_contains = ["owner EMAIL_"]
expect_not_contains = ["jean@example.com"]
"#;

    #[cfg(logano_templates)]
    #[test]
    fn a_template_text_is_checked_without_being_saved() {
        let (state, root) = state("check");
        let c = check_template(&state, MINE);
        assert!(c.ok, "{:?}", c.error);
        assert_eq!((c.id.as_deref(), c.exists, c.builtin), (Some("equipe/demo"), false, false));
        assert_eq!(c.tests.len(), 1);
        // Ce qui affaiblit la protection est listé pour relecture.
        assert_eq!(c.weakens.len(), 3, "{:?}", c.weakens);
        assert!(c.weakens.iter().any(|w| w.contains("kbrw/common:phones")) && c.weakens.iter().any(|w| w.contains("order_ref")));
        assert!(state.library.read().unwrap().get("equipe/demo").is_none());

        // TOML invalide, champ inconnu, parent absent, test qui échoue : un état, pas une panique.
        assert!(check_template(&state, "pas du toml [").error.is_some());
        assert!(check_template(&state, &MINE.replace("log_kind", "exec")).error.unwrap().contains("exec"));
        assert!(!check_template(&state, &MINE.replace("kbrw/elixir@^1", "kbrw/elixir@^9")).ok);
        let failing = check_template(&state, &MINE.replace("owner EMAIL_", "owner jean"));
        assert!(!failing.ok && !failing.tests[0].passed);
        // Un identifiant de template fourni est signalé.
        let builtin = check_template(&state, &MINE.replace("equipe/demo", "kbrw/elixir").replace("extends = [\"kbrw/elixir@^1\"]", "extends = [\"kbrw/common@^1\"]"));
        assert!(builtin.builtin && builtin.exists);
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(logano_templates)]
    #[test]
    fn a_user_template_is_saved_reloaded_and_deleted() {
        let (state, root) = state("save");
        let path = crate::local::user_path(&state, "equipe/demo");
        crate::local::write_validated(&state, "equipe/demo", &path, MINE).unwrap();
        assert!(path.ends_with("templates/equipe/demo.toml") && path.exists());
        let lib = state.library.read().unwrap().clone();
        assert!(lib.get("equipe/demo").is_some() && !lib.is_builtin("equipe/demo"));
        assert_eq!(lib.source("equipe/demo"), Some(MINE));
        // Une version invalide est refusée et l'ancienne reste en place.
        assert!(crate::local::write_validated(&state, "equipe/demo", &path, &MINE.replace("strategy = \"keep\"", "strategy = \"teleport\"")).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MINE);
        assert!(check_template(&state, MINE).exists);

        crate::local::delete(&state, "equipe/demo").unwrap();
        assert!(!path.exists() && state.library.read().unwrap().get("equipe/demo").is_none());
        assert!(crate::local::delete(&state, "kbrw/elixir").is_err());
        std::fs::remove_dir_all(&root).ok();
    }
}

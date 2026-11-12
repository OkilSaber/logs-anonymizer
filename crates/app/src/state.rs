//! État partagé de l'app.

use crate::config::{AppConfig, Dirs};
use crate::error::{AppError, AppResult};
use logano_core::glob::glob_match_ci;
use logano_core::Library;
use logano_remote::{BastionConfig, CancellationToken, ConnectOptions, RemoteSession, SecretString, ServerConfig, SessionPool};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};

/// Une sortie anonymisée produite par un run. L'interface ne connaît que son identifiant :
/// copie et export ne prennent jamais de chemin.
#[derive(Clone)]
pub struct OutputInfo {
    /// Fichiers de la sortie, dans l'ordre : un seul, ou plusieurs parties.
    pub paths: Vec<PathBuf>,
    /// Fichiers du cache brut dont elle vient, un par jour, dans l'ordre.
    pub raw_paths: Vec<PathBuf>,
    pub days: Vec<String>,
    pub app: String,
    /// `erlang`, `haproxy` ou `console`.
    pub kind: String,
    /// Template avec lequel la sortie a été produite.
    pub template: String,
    /// Clé du run, en mémoire seulement : l'aperçu côte à côte redonne les mêmes jetons.
    pub key: [u8; 32],
    pub quarantined: bool,
    pub file_name: String,
}

pub struct RunHandle {
    pub token: CancellationToken,
    pub flag: Arc<AtomicBool>,
}

pub struct AppState {
    pub dirs: Dirs,
    pub config: RwLock<AppConfig>,
    pub library: RwLock<Library>,
    pool: tokio::sync::Mutex<Option<(BastionConfig, Arc<SessionPool>)>>,
    /// Mots de passe sudo par serveur : en mémoire seulement, jamais écrits.
    pub sudo_passwords: Mutex<HashMap<String, SecretString>>,
    /// Phrases de passe par fichier de clé : en mémoire seulement.
    pub key_passphrases: Mutex<HashMap<String, SecretString>>,
    pub runs: Mutex<HashMap<String, RunHandle>>,
    pub outputs: Mutex<HashMap<String, OutputInfo>>,
    /// Clé du bac à sable : stable pendant la session pour que les jetons ne changent pas à chaque frappe.
    pub sandbox_key: [u8; 32],
}

impl AppState {
    pub fn init(dirs: Dirs) -> AppResult<Self> {
        std::fs::create_dir_all(&dirs.data)?;
        let config = AppConfig::load(&dirs.config_path())?;
        let mut library = Library::builtin();
        // Les templates de l'utilisateur s'ajoutent aux templates fournis ; un fichier invalide
        // n'empêche pas l'app de démarrer.
        let _ = library.load_dir(&dirs.user_templates());
        Ok(AppState {
            dirs,
            config: RwLock::new(config),
            library: RwLock::new(library),
            pool: tokio::sync::Mutex::new(None),
            sudo_passwords: Mutex::new(HashMap::new()),
            key_passphrases: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            outputs: Mutex::new(HashMap::new()),
            sandbox_key: rand::random(),
        })
    }

    pub fn config(&self) -> AppConfig {
        self.config.read().expect("verrou config").clone()
    }

    /// Pool SSH pour le bastion courant ; recréé si la config du bastion a changé.
    pub async fn pool(&self) -> AppResult<Arc<SessionPool>> {
        let bastion = self
            .config()
            .bastion
            .ok_or_else(|| AppError::new("no_bastion", "Aucun bastion configuré : renseigne-le dans les réglages."))?;
        let mut guard = self.pool.lock().await;
        if let Some((current, pool)) = guard.as_ref() {
            if *current == bastion {
                return Ok(pool.clone());
            }
        }
        if let Some((_, old)) = guard.take() {
            old.close().await;
        }
        let options = ConnectOptions { known_hosts_path: Some(self.dirs.known_hosts()), ..Default::default() };
        let pool = Arc::new(SessionPool::new(bastion.clone(), options));
        for (file, pass) in self.key_passphrases.lock().expect("verrou phrases de passe").iter() {
            pool.set_key_passphrase(file, Some(pass.clone()));
        }
        *guard = Some((bastion, pool.clone()));
        Ok(pool)
    }

    pub async fn session(&self, server_id: &str) -> AppResult<(ServerConfig, Arc<RemoteSession>)> {
        let server = self
            .config()
            .servers
            .into_iter()
            .find(|s| s.id == server_id)
            .ok_or_else(|| AppError::new("unknown_server", format!("Serveur « {server_id} » inconnu.")))?;
        let session = self.pool().await?.session(&server).await?;
        Ok((server, session))
    }

    pub fn sudo_password(&self, server_id: &str) -> Option<SecretString> {
        self.sudo_passwords.lock().expect("verrou sudo").get(server_id).cloned()
    }
}

impl AppState {
    /// Template qu'un nouveau run utiliserait pour cette sortie. Il diffère de celui de la
    /// sortie quand le template local de l'application a été créé ou modifié depuis : l'aperçu
    /// et le profil montrent alors l'effet du changement sans attendre un nouveau run.
    pub fn current_template(&self, info: &OutputInfo) -> String {
        let lib = self.library.read().expect("verrou bibliothèque");
        let local = crate::local::local_id(&info.app, &info.kind);
        // Un template choisi à la main pour le run reste celui du run, sauf si l'app a
        // depuis un template local, qui passe devant.
        if lib.get(&local).is_some() && lib.compile(&local).is_ok() {
            return local;
        }
        info.template.clone()
    }
}

/// Template d'un fichier : celui imposé, sinon une association de la config, sinon le
/// template dont `suggested_apps` désigne l'app le plus précisément, sinon le socle du type.
pub fn pick_template(lib: &Library, cfg: &AppConfig, app: &str, kind: &str, forced: Option<&str>) -> Option<String> {
    if let Some(f) = forced.filter(|f| !f.is_empty()) {
        return Some(f.to_string());
    }
    if let Some(a) = cfg.associations.iter().find(|a| a.log_kind == kind && glob_match_ci(&a.app, app)) {
        return Some(a.template.clone());
    }
    let mut best: Option<(usize, &str)> = None;
    for id in lib.ids() {
        let Some(file) = lib.get(id) else { continue };
        let meta = &file.template;
        if meta.is_abstract || meta.log_kind.as_deref() != Some(kind) {
            continue;
        }
        for pattern in &meta.suggested_apps {
            if glob_match_ci(pattern, app) {
                // Le motif le plus précis est celui qui a le plus de caractères littéraux ;
                // à égalité, le template local de l'app passe devant.
                let score = pattern.chars().filter(|c| *c != '*' && *c != '?').count() * 2 + usize::from(id.starts_with("local/"));
                if best.is_none_or(|(s, _)| score > s) {
                    best = Some((score, id));
                }
            }
        }
    }
    best.map(|(_, id)| id.to_string())
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;
    use crate::config::Association;

    #[cfg(logano_templates)]
    #[test]
    fn picks_the_most_specific_template() {
        let lib = Library::builtin();
        let mut cfg = AppConfig::default();
        assert_eq!(pick_template(&lib, &cfg, "etam_sb_gateway", "erlang", None).as_deref(), Some("etam/gateway"));
        // Les noms de prod n'ont pas de segment d'environnement.
        assert_eq!(pick_template(&lib, &cfg, "etam_gateway", "erlang", None).as_deref(), Some("etam/gateway"));
        assert_eq!(pick_template(&lib, &cfg, "etam_services", "erlang", None).as_deref(), Some("etam/services"));
        assert_eq!(pick_template(&lib, &cfg, "etam_sb_services", "erlang", None).as_deref(), Some("etam/services"));
        // Chaque projet a son template ; les autres apps Etam prennent celui du projet.
        for (app, template) in [
            ("etam_sb_admin", "etam/apps"),
            ("etam_sup", "etam/apps"),
            ("jar_sb_admin", "jar/apps"),
            ("psareturn_services", "psareturn/apps"),
            ("fpx_lad_gateway_in", "fpx/apps"),
            ("franprix_lad", "fpx/apps"),
            ("ladfpadmin", "fpx/apps"),
            ("clog_sb_services", "clog/apps"),
            ("clogclr_admin", "clogclr/apps"),
            ("bapif_sb_cms_ui", "bapif/apps"),
            ("cms_ui", "bapif/apps"),
            ("crfes_sb_crfes_picker", "crfes/apps"),
            ("tot_sb_sup", "tot/apps"),
            ("iam", "kbrw/platform"),
            ("portal", "kbrw/platform"),
            // Une app inconnue, ou le erlang.log de Riak, retombe sur le socle.
            ("autre_app", "kbrw/elixir"),
            ("riakn", "kbrw/elixir"),
        ] {
            assert_eq!(pick_template(&lib, &cfg, app, "erlang", None).as_deref(), Some(template), "{app}");
        }
        assert_eq!(pick_template(&lib, &cfg, "etam_sb_gateway", "haproxy", None).as_deref(), Some("kbrw/haproxy"));
        assert_eq!(pick_template(&lib, &cfg, "riakn", "console", None).as_deref(), Some("kbrw/riak-console"));
        cfg.associations.push(Association { app: "jar_*".into(), log_kind: "erlang".into(), template: "etam/gateway".into() });
        assert_eq!(pick_template(&lib, &cfg, "jar_sb_admin", "erlang", None).as_deref(), Some("etam/gateway"));
        assert_eq!(pick_template(&lib, &cfg, "jar_sb_admin", "erlang", Some("kbrw/elixir")).as_deref(), Some("kbrw/elixir"));
    }
}

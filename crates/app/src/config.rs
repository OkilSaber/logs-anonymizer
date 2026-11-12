//! Configuration de l'app : `config.toml` dans le dossier de données, versionnée.

use crate::error::{AppError, AppResult};
use logano_remote::{BastionConfig, ServerConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Association {
    /// Glob sur le nom d'app : `etam_*_gateway`.
    pub app: String,
    pub log_kind: String,
    pub template: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Transfer {
    /// Confirmation demandée au-delà de cette taille à télécharger, en octets.
    pub confirm_above: u64,
    /// Fichiers téléchargés en même temps, sur la même connexion SSH.
    pub parallel_downloads: u32,
    /// Fichiers anonymisés en même temps.
    pub parallel_processing: u32,
}

/// Borne des deux réglages de parallélisme. Un serveur OpenSSH accepte 10 sessions par
/// connexion (`MaxSessions`) : on reste en dessous.
pub const MAX_PARALLEL: u32 = 8;

impl Transfer {
    pub fn downloads(&self) -> usize {
        self.parallel_downloads.clamp(1, MAX_PARALLEL) as usize
    }

    pub fn processing(&self) -> usize {
        self.parallel_processing.clamp(1, MAX_PARALLEL) as usize
    }
}

impl Default for Transfer {
    fn default() -> Self {
        Transfer { confirm_above: 1 << 30, parallel_downloads: 3, parallel_processing: 2 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Output {
    /// Vide : `<Documents>/LogsAnonymizer`.
    pub dir: String,
    /// `compact` ou `faithful`.
    pub layout: String,
    pub header: bool,
    /// Taille visée d'une partie de sortie, en tokens estimés ; 0 = un seul fichier.
    pub chunk_tokens: u64,
}

impl Default for Output {
    fn default() -> Self {
        Output { dir: String::new(), layout: "compact".into(), header: true, chunk_tokens: 0 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Cache {
    /// Taille maximale du cache brut, en octets ; 0 = pas de limite. Après chaque run,
    /// les fichiers téléchargés les plus anciens sont supprimés pour repasser dessous.
    pub max_size: u64,
}

impl Default for Cache {
    fn default() -> Self {
        Cache { max_size: 50 << 30 }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Pseudonyms {
    /// Garder, chiffrée, la table jeton → valeur réelle de chaque run.
    pub mapping_table: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SafetyNet {
    /// `replace` ou `report`.
    pub action: String,
}

impl Default for SafetyNet {
    fn default() -> Self {
        SafetyNet { action: "replace".into() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub config_version: u32,
    pub bastion: Option<BastionConfig>,
    pub servers: Vec<ServerConfig>,
    pub associations: Vec<Association>,
    pub transfer: Transfer,
    pub cache: Cache,
    pub output: Output,
    pub safety_net: SafetyNet,
    pub pseudonyms: Pseudonyms,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            config_version: CONFIG_VERSION,
            bastion: None,
            servers: Vec::new(),
            associations: Vec::new(),
            transfer: Transfer::default(),
            cache: Cache::default(),
            output: Output::default(),
            safety_net: SafetyNet::default(),
            pseudonyms: Pseudonyms::default(),
        }
    }
}

impl AppConfig {
    /// Charge la config ; absente, rend la config par défaut. Une version plus récente
    /// que celle de l'app est refusée plutôt que tronquée.
    pub fn load(path: &Path) -> AppResult<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AppConfig::default()),
            Err(e) => return Err(e.into()),
        };
        let mut cfg: AppConfig = toml::from_str(&text).map_err(|e| AppError::new("config_invalid", format!("config.toml illisible : {e}")))?;
        if cfg.config_version > CONFIG_VERSION {
            return Err(AppError::new(
                "config_too_recent",
                format!("config.toml est en version {} ; cette app ne connaît que la version {CONFIG_VERSION}", cfg.config_version),
            ));
        }
        // Migrations : rien avant la version 1.
        cfg.config_version = CONFIG_VERSION;
        Ok(cfg)
    }

    /// Écriture atomique : fichier temporaire puis renommage.
    pub fn save(&self, path: &Path) -> AppResult<()> {
        let text = toml::to_string_pretty(self).map_err(|e| AppError::new("config_invalid", format!("config non sérialisable : {e}")))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Dirs {
    pub data: PathBuf,
    /// Cache brut : jamais dans les sorties.
    pub raw_cache: PathBuf,
    pub default_output: PathBuf,
}

impl Dirs {
    pub fn config_path(&self) -> PathBuf {
        self.data.join("config.toml")
    }

    /// Tables de correspondance chiffrées, une par run.
    pub fn mappings(&self) -> PathBuf {
        self.data.join("maps")
    }

    pub fn history(&self) -> PathBuf {
        self.data.join("history.json")
    }

    pub fn known_hosts(&self) -> PathBuf {
        self.data.join("known_hosts.json")
    }

    pub fn user_templates(&self) -> PathBuf {
        self.data.join("templates")
    }

    pub fn output_root(&self, cfg: &AppConfig) -> PathBuf {
        if cfg.output.dir.trim().is_empty() {
            self.default_output.clone()
        } else {
            logano_remote::expand_tilde(cfg.output.dir.trim())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_defaults() {
        let dir = std::env::temp_dir().join(format!("logano-app-config-{}", std::process::id()));
        let path = dir.join("config.toml");
        assert_eq!(AppConfig::load(&path).unwrap(), AppConfig::default());
        let mut cfg = AppConfig { bastion: Some(BastionConfig::new("access01.cloud.kbrwadventure.com", "jdupont")), ..Default::default() };
        cfg.servers.push(ServerConfig::new("etam-sb", "Etam — sandbox", "syslogserver01.priv.etamadm-sb.kbrw.fr"));
        cfg.associations.push(Association { app: "etam_*_gateway".into(), log_kind: "erlang".into(), template: "etam/gateway".into() });
        cfg.save(&path).unwrap();
        assert_eq!(AppConfig::load(&path).unwrap(), cfg);
        std::fs::write(&path, "config_version = 99\n").unwrap();
        assert_eq!(AppConfig::load(&path).unwrap_err().code, "config_too_recent");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn architecture_example_parses() {
        let text = r#"
config_version = 1
[bastion]
host = "access01.cloud.kbrwadventure.com"
user = "jdupont"
auth = "key"
identity_file = "~/.ssh/id_rsa"
mode = "nc"
[[servers]]
id = "etam-sb"
name = "Etam — sandbox"
host = "syslogserver01.priv.etamadm-sb.kbrw.fr"
[[associations]]
app = "etam_*_gateway"
log_kind = "erlang"
template = "etam/gateway"
[output]
layout = "compact"
"#;
        let cfg: AppConfig = toml::from_str(text).unwrap();
        assert_eq!(cfg.servers[0].id, "etam-sb");
        assert_eq!(cfg.bastion.unwrap().user, "jdupont");
        assert_eq!(cfg.transfer.confirm_above, 1 << 30);
        // Réglages absents d'une config plus ancienne : valeurs par défaut.
        assert_eq!((cfg.transfer.downloads(), cfg.transfer.processing()), (3, 2));
        let wild: AppConfig = toml::from_str("[transfer]\nparallel_downloads = 0\nparallel_processing = 99\n").unwrap();
        assert_eq!((wild.transfer.downloads(), wild.transfer.processing()), (1, 8));
    }
}

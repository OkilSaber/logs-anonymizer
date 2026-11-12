//! Types de configuration : bastion, serveurs, authentification.
//!
//! Ces types sont faits pour être embarqués tels quels dans le `config.toml`
//! de l'application. La forme sérialisée suit `docs/ARCHITECTURE.md` §12 :
//! `auth = "key" | "agent"` et `identity_file = "…"` sont des clés à plat du
//! bastion (ou du serveur), pas une sous-table.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Motif de chemin par défaut des logs sur les serveurs syslog.
pub const DEFAULT_PATH_PATTERN: &str = "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/";
/// Commande exécutée sur le bastion en mode `nc`.
pub const DEFAULT_NC_COMMAND: &str = "nc {host} {port}";
/// Clé privée utilisée par défaut.
pub const DEFAULT_IDENTITY_FILE: &str = "~/.ssh/id_rsa";

fn default_port() -> u16 {
    22
}
fn default_nc_command() -> String {
    DEFAULT_NC_COMMAND.to_string()
}
fn default_keepalive() -> u64 {
    60
}
fn default_path_pattern() -> String {
    DEFAULT_PATH_PATTERN.to_string()
}

/// Méthode d'authentification SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthConfig {
    /// Clé privée sur disque. `~` est étendu au moment de la connexion.
    Key { identity_file: String },
    /// Clés détenues par ssh-agent (`SSH_AUTH_SOCK`).
    Agent,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig::Key {
            identity_file: DEFAULT_IDENTITY_FILE.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthKind {
    Key,
    Agent,
}

/// (`auth`, `identity_file`) à plat → `AuthConfig`. `None` si rien n'est précisé.
fn auth_from_parts(kind: Option<AuthKind>, identity_file: Option<String>) -> Option<AuthConfig> {
    match (kind, identity_file) {
        (Some(AuthKind::Agent), _) => Some(AuthConfig::Agent),
        (Some(AuthKind::Key), file) => Some(AuthConfig::Key {
            identity_file: file.unwrap_or_else(|| DEFAULT_IDENTITY_FILE.to_string()),
        }),
        (None, Some(file)) => Some(AuthConfig::Key {
            identity_file: file,
        }),
        (None, None) => None,
    }
}

fn auth_to_parts(auth: &AuthConfig) -> (Option<AuthKind>, Option<String>) {
    match auth {
        AuthConfig::Key { identity_file } => (Some(AuthKind::Key), Some(identity_file.clone())),
        AuthConfig::Agent => (Some(AuthKind::Agent), None),
    }
}

/// Façon de traverser le bastion pour atteindre un serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JumpMode {
    /// `nc <host> <port>` exécuté sur le bastion (comme `ProxyCommand ssh bastion "nc %h %p"`).
    #[default]
    Nc,
    /// Canal `direct-tcpip` (équivalent de `ProxyJump` / `ssh -W`).
    #[serde(alias = "direct-tcpip")]
    DirectTcpip,
}

/// Vérification de la clé d'hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyPolicy {
    /// Accepte n'importe quelle clé (comme `StrictHostKeyChecking no`).
    #[default]
    Insecure,
    /// Enregistre l'empreinte au premier contact, refuse si elle change ensuite.
    Tofu,
}

/// Bastion SSH par lequel passent toutes les connexions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "BastionRepr", into = "BastionRepr")]
pub struct BastionConfig {
    pub host: String,
    /// 22 par défaut.
    pub port: u16,
    pub user: String,
    /// Clé `~/.ssh/id_rsa` par défaut.
    pub auth: AuthConfig,
    /// `nc` par défaut.
    pub mode: JumpMode,
    /// Commande du mode `nc` ; `{host}` et `{port}` sont remplacés par ceux du serveur cible.
    pub nc_command: String,
    /// S'applique au bastion et aux serveurs atteints à travers lui.
    pub host_key_policy: HostKeyPolicy,
    /// Intervalle de keepalive en secondes (0 = désactivé). 60 par défaut.
    pub keepalive_secs: u64,
}

impl BastionConfig {
    /// Bastion avec toutes les valeurs par défaut.
    pub fn new(host: impl Into<String>, user: impl Into<String>) -> Self {
        BastionConfig {
            host: host.into(),
            port: default_port(),
            user: user.into(),
            auth: AuthConfig::default(),
            mode: JumpMode::default(),
            nc_command: default_nc_command(),
            host_key_policy: HostKeyPolicy::default(),
            keepalive_secs: default_keepalive(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BastionRepr {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_file: Option<String>,
    #[serde(default)]
    mode: JumpMode,
    #[serde(default = "default_nc_command")]
    nc_command: String,
    #[serde(default)]
    host_key_policy: HostKeyPolicy,
    #[serde(default = "default_keepalive")]
    keepalive_secs: u64,
}

impl From<BastionRepr> for BastionConfig {
    fn from(r: BastionRepr) -> Self {
        BastionConfig {
            host: r.host,
            port: r.port,
            user: r.user,
            auth: auth_from_parts(r.auth, r.identity_file).unwrap_or_default(),
            mode: r.mode,
            nc_command: r.nc_command,
            host_key_policy: r.host_key_policy,
            keepalive_secs: r.keepalive_secs,
        }
    }
}

impl From<BastionConfig> for BastionRepr {
    fn from(c: BastionConfig) -> Self {
        let (auth, identity_file) = auth_to_parts(&c.auth);
        BastionRepr {
            host: c.host,
            port: c.port,
            user: c.user,
            auth,
            identity_file,
            mode: c.mode,
            nc_command: c.nc_command,
            host_key_policy: c.host_key_policy,
            keepalive_secs: c.keepalive_secs,
        }
    }
}

/// Serveur de logs. `user`, `auth` et `bastion` absents reprennent ceux du
/// bastion utilisé (le bastion propre du serveur s'il en a un, sinon le global).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ServerRepr", into = "ServerRepr")]
pub struct ServerConfig {
    /// Identifiant stable (sert de dossier dans le cache).
    pub id: String,
    /// Nom affiché.
    pub name: String,
    pub host: String,
    /// 22 par défaut.
    pub port: u16,
    pub user: Option<String>,
    pub auth: Option<AuthConfig>,
    pub bastion: Option<BastionConfig>,
    /// Motif du dossier des fichiers, avec `{YYYY}`, `{MM}`, `{DD}`, `{app_name}`, `{cluster}`.
    pub path_pattern: String,
}

impl ServerConfig {
    /// Serveur avec toutes les valeurs par défaut.
    pub fn new(id: impl Into<String>, name: impl Into<String>, host: impl Into<String>) -> Self {
        ServerConfig {
            id: id.into(),
            name: name.into(),
            host: host.into(),
            port: default_port(),
            user: None,
            auth: None,
            bastion: None,
            path_pattern: default_path_pattern(),
        }
    }

    /// Bastion réellement utilisé pour ce serveur.
    pub fn effective_bastion<'a>(&'a self, global: &'a BastionConfig) -> &'a BastionConfig {
        self.bastion.as_ref().unwrap_or(global)
    }

    /// Utilisateur réellement utilisé sur ce serveur.
    pub fn effective_user<'a>(&'a self, global: &'a BastionConfig) -> &'a str {
        self.user
            .as_deref()
            .unwrap_or(&self.effective_bastion(global).user)
    }

    /// Authentification réellement utilisée sur ce serveur.
    pub fn effective_auth<'a>(&'a self, global: &'a BastionConfig) -> &'a AuthConfig {
        self.auth
            .as_ref()
            .unwrap_or(&self.effective_bastion(global).auth)
    }
}

#[derive(Serialize, Deserialize)]
struct ServerRepr {
    id: String,
    name: String,
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<AuthKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_file: Option<String>,
    #[serde(default = "default_path_pattern")]
    path_pattern: String,
    // En dernier : c'est une table en TOML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bastion: Option<BastionConfig>,
}

impl From<ServerRepr> for ServerConfig {
    fn from(r: ServerRepr) -> Self {
        ServerConfig {
            id: r.id,
            name: r.name,
            host: r.host,
            port: r.port,
            user: r.user,
            auth: auth_from_parts(r.auth, r.identity_file),
            bastion: r.bastion,
            path_pattern: r.path_pattern,
        }
    }
}

impl From<ServerConfig> for ServerRepr {
    fn from(c: ServerConfig) -> Self {
        let (auth, identity_file) = match &c.auth {
            Some(a) => auth_to_parts(a),
            None => (None, None),
        };
        ServerRepr {
            id: c.id,
            name: c.name,
            host: c.host,
            port: c.port,
            user: c.user,
            auth,
            identity_file,
            path_pattern: c.path_pattern,
            bastion: c.bastion,
        }
    }
}

/// Étend un `~` initial avec `$HOME`. Les autres chemins sont rendus tels quels.
pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct AppConfig {
        bastion: BastionConfig,
        #[serde(default)]
        servers: Vec<ServerConfig>,
    }

    /// Extrait du `config.toml` de `docs/ARCHITECTURE.md` §12.
    const ARCHI_TOML: &str = r#"
[bastion]
host = "access01.cloud.kbrwadventure.com"
user = "jdupont"
port = 22
auth = "key"
identity_file = "~/.ssh/id_rsa"
mode = "nc"
nc_command = "nc {host} {port}"
host_key_policy = "insecure"
keepalive_secs = 60

[[servers]]
id = "etam-sb"
name = "Etam — sandbox"
host = "syslogserver01.priv.etamadm-sb.kbrw.fr"
user = "jdupont"
path_pattern = "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/"
"#;

    #[test]
    fn lit_le_toml_de_l_architecture() {
        let cfg: AppConfig = toml::from_str(ARCHI_TOML).unwrap();
        assert_eq!(cfg.bastion.host, "access01.cloud.kbrwadventure.com");
        assert_eq!(cfg.bastion.port, 22);
        assert_eq!(cfg.bastion.mode, JumpMode::Nc);
        assert_eq!(cfg.bastion.host_key_policy, HostKeyPolicy::Insecure);
        assert_eq!(cfg.bastion.keepalive_secs, 60);
        assert_eq!(
            cfg.bastion.auth,
            AuthConfig::Key {
                identity_file: "~/.ssh/id_rsa".into()
            }
        );
        let s = &cfg.servers[0];
        assert_eq!(s.id, "etam-sb");
        assert_eq!(s.user.as_deref(), Some("jdupont"));
        assert_eq!(s.auth, None);
        assert_eq!(s.bastion, None);
        assert_eq!(s.port, 22);
    }

    #[test]
    fn valeurs_par_defaut() {
        let cfg: AppConfig = toml::from_str(
            r#"
[bastion]
host = "b"
user = "u"

[[servers]]
id = "s"
name = "S"
host = "h"
"#,
        )
        .unwrap();
        assert_eq!(cfg.bastion, BastionConfig::new("b", "u"));
        assert_eq!(cfg.bastion.nc_command, "nc {host} {port}");
        assert_eq!(cfg.servers[0], ServerConfig::new("s", "S", "h"));
        assert_eq!(cfg.servers[0].path_pattern, DEFAULT_PATH_PATTERN);
    }

    #[test]
    fn aller_retour_toml_et_json() {
        let mut bastion = BastionConfig::new("b", "u");
        bastion.auth = AuthConfig::Agent;
        bastion.mode = JumpMode::DirectTcpip;
        bastion.host_key_policy = HostKeyPolicy::Tofu;
        let mut server = ServerConfig::new("s", "S", "h");
        server.auth = Some(AuthConfig::Key {
            identity_file: "~/.ssh/autre".into(),
        });
        server.bastion = Some(BastionConfig::new("b2", "u2"));
        server.port = 2222;
        let cfg = AppConfig {
            bastion,
            servers: vec![server, ServerConfig::new("t", "T", "h2")],
        };

        let text = toml::to_string(&cfg).unwrap();
        assert!(text.contains("auth = \"agent\""), "{text}");
        assert!(text.contains("mode = \"direct_tcpip\""), "{text}");
        assert!(text.contains("identity_file = \"~/.ssh/autre\""), "{text}");
        let back: AppConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.bastion, cfg.bastion);
        assert_eq!(back.servers, cfg.servers);

        let json = serde_json::to_string(&cfg).unwrap();
        let back: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.servers, cfg.servers);
    }

    #[test]
    fn identity_file_seul_vaut_auth_par_cle() {
        let s: ServerConfig = toml::from_str(
            "id = \"s\"\nname = \"S\"\nhost = \"h\"\nidentity_file = \"~/.ssh/k\"\n",
        )
        .unwrap();
        assert_eq!(
            s.auth,
            Some(AuthConfig::Key {
                identity_file: "~/.ssh/k".into()
            })
        );
    }

    #[test]
    fn heritage_du_bastion() {
        let global = BastionConfig::new("b", "moi");
        let mut s = ServerConfig::new("s", "S", "h");
        assert_eq!(s.effective_user(&global), "moi");
        assert_eq!(s.effective_auth(&global), &AuthConfig::default());
        let mut own = BastionConfig::new("b2", "autre");
        own.auth = AuthConfig::Agent;
        s.bastion = Some(own);
        assert_eq!(s.effective_bastion(&global).host, "b2");
        assert_eq!(s.effective_user(&global), "autre");
        assert_eq!(s.effective_auth(&global), &AuthConfig::Agent);
        s.user = Some("x".into());
        assert_eq!(s.effective_user(&global), "x");
    }

    #[test]
    fn tilde() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            expand_tilde("~/.ssh/id_rsa"),
            PathBuf::from(&home).join(".ssh/id_rsa")
        );
        assert_eq!(expand_tilde("/abs/key"), PathBuf::from("/abs/key"));
        assert_eq!(expand_tilde("~autre/key"), PathBuf::from("~autre/key"));
    }
}

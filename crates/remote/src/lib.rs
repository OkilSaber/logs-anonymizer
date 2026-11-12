//! `logano-remote` : accès aux serveurs syslog à travers un bastion SSH.
//!
//! Tout passe par des canaux exec (pas de SFTP dans ce MVP) :
//!
//! 1. [`SessionPool`] ouvre une session sur le bastion, puis une session par
//!    serveur à travers lui (`nc <host> <port>` sur le bastion, ou `direct-tcpip`).
//! 2. [`RemoteSession`] exécute des commandes : découverte des apps et des
//!    fichiers d'un jour, `sudo chmod +r`, téléchargement vers un gzip local.
//! 3. [`RawCache`] range les fichiers bruts téléchargés et dit s'ils sont
//!    encore valables.
//! 4. [`import_ssh_config`] propose une configuration à partir de
//!    `~/.ssh/config`, `~/.zshrc` et l'historique du shell.
//!
//! Voir `README.md` pour la liste complète des types et des signatures.

mod cache;
mod config;
mod discover;
mod download;
mod error;
mod hostkeys;
mod import;
mod pool;
mod session;
mod shell;
mod sudo;

pub use cache::{CacheLookup, CacheMeta, Evicted, RawCache, StaleReason};
pub use config::{
    expand_tilde, AuthConfig, BastionConfig, HostKeyPolicy, JumpMode, ServerConfig,
    DEFAULT_IDENTITY_FILE, DEFAULT_NC_COMMAND, DEFAULT_PATH_PATTERN,
};
pub use discover::{AppInfo, LogKind, RemoteFile};
pub use download::{Compression, DownloadOutcome};
pub use error::{RemoteError, Result};
pub use import::{import_ssh_config, ImportProposal};
pub use pool::{PoolStats, SessionPool};
pub use session::{ConnectOptions, ExecOutput, ExecStream, RemoteSession};
pub use shell::shell_quote;

// Types des paramètres de l'API, réexportés pour que l'appelant n'ait pas à
// aligner ses versions de dépendances.
pub use secrecy::SecretString;
pub use tokio_util::sync::CancellationToken;

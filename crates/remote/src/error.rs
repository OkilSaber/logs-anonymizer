//! Erreurs typées de l'accès distant.

use std::path::PathBuf;

use chrono::NaiveDate;

/// Erreur de l'accès distant. Chaque variante correspond à une situation que
/// l'interface doit pouvoir distinguer ; les messages sont en français et ne
/// contiennent jamais de secret (mot de passe sudo, phrase de passe).
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    /// Le bastion ne répond pas (réseau, DNS, port fermé, délai dépassé).
    #[error("Bastion injoignable ({host}:{port}) : {detail}")]
    BastionUnreachable {
        host: String,
        port: u16,
        detail: String,
    },

    /// Le serveur cible ne répond pas à travers le bastion.
    #[error("Serveur injoignable à travers le bastion ({host}:{port}) : {detail}")]
    TargetUnreachable {
        host: String,
        port: u16,
        detail: String,
    },

    /// Le serveur a refusé la clé (ou toutes les clés de l'agent).
    #[error("Clé SSH refusée par {host} pour l'utilisateur {user}")]
    KeyRejected { host: String, user: String },

    /// La clé privée est chiffrée et aucune phrase de passe n'a été fournie.
    #[error("La clé {identity_file} est chiffrée : phrase de passe requise")]
    KeyPassphraseRequired { identity_file: String },

    /// La phrase de passe fournie ne déchiffre pas la clé.
    #[error("Phrase de passe incorrecte pour la clé {identity_file}")]
    KeyPassphraseInvalid { identity_file: String },

    /// Le fichier de clé est absent ou illisible.
    #[error("Clé SSH illisible ({identity_file}) : {detail}")]
    KeyUnreadable {
        identity_file: String,
        detail: String,
    },

    /// ssh-agent est injoignable (`SSH_AUTH_SOCK` absent ou invalide).
    #[error("ssh-agent indisponible : {detail}")]
    AgentUnavailable { detail: String },

    /// Mode TOFU : l'empreinte de la clé d'hôte a changé depuis le premier contact.
    #[error(
        "La clé d'hôte de {host}:{port} a changé (attendue {expected}, reçue {actual}). \
         Connexion refusée."
    )]
    HostKeyChanged {
        host: String,
        port: u16,
        expected: String,
        actual: String,
    },

    /// sudo exige un mot de passe et aucun n'a été fourni.
    #[error("sudo demande un mot de passe sur {server}")]
    SudoPasswordRequired { server: String },

    /// sudo a refusé (mauvais mot de passe, utilisateur non sudoer) ou le chmod a échoué.
    #[error("sudo chmod refusé sur {server} : {stderr}")]
    SudoDenied { server: String, stderr: String },

    /// Le dossier du jour n'existe pas sur le serveur.
    #[error("Aucun dossier de logs pour le {day} sur {server} ({path})")]
    DayNotFound {
        server: String,
        day: NaiveDate,
        path: String,
    },

    /// Le fichier ou le dossier demandé n'existe pas sur le serveur.
    #[error("Fichier ou dossier absent sur {server} : {path}")]
    FileNotFound { server: String, path: String },

    /// Le transfert s'est arrêté avant la fin (flux coupé, statut de sortie non nul).
    #[error("Transfert interrompu pour {path} : {detail}")]
    TransferInterrupted { path: String, detail: String },

    /// L'opération a été annulée par l'appelant.
    #[error("Opération annulée")]
    Cancelled,

    /// Erreur d'entrée/sortie sur le disque local.
    #[error("Erreur d'écriture ou de lecture locale ({path}) : {source}")]
    LocalIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Une commande distante a échoué pour une raison non couverte ci-dessus.
    #[error("Commande distante en échec sur {server} (statut {exit_status:?}) : {stderr}")]
    CommandFailed {
        server: String,
        exit_status: Option<u32>,
        stderr: String,
    },

    /// La session SSH est tombée pendant une opération.
    #[error("Session SSH perdue avec {server} : {detail}")]
    SessionLost { server: String, detail: String },

    /// La configuration est incohérente (motif de chemin, TOFU sans fichier, nom invalide).
    #[error("Configuration invalide : {detail}")]
    InvalidConfig { detail: String },
}

impl RemoteError {
    /// Identifiant stable de la variante, pratique pour brancher l'interface
    /// (par exemple demander un mot de passe sur `sudo_password_required`).
    pub fn code(&self) -> &'static str {
        match self {
            RemoteError::BastionUnreachable { .. } => "bastion_unreachable",
            RemoteError::TargetUnreachable { .. } => "target_unreachable",
            RemoteError::KeyRejected { .. } => "key_rejected",
            RemoteError::KeyPassphraseRequired { .. } => "key_passphrase_required",
            RemoteError::KeyPassphraseInvalid { .. } => "key_passphrase_invalid",
            RemoteError::KeyUnreadable { .. } => "key_unreadable",
            RemoteError::AgentUnavailable { .. } => "agent_unavailable",
            RemoteError::HostKeyChanged { .. } => "host_key_changed",
            RemoteError::SudoPasswordRequired { .. } => "sudo_password_required",
            RemoteError::SudoDenied { .. } => "sudo_denied",
            RemoteError::DayNotFound { .. } => "day_not_found",
            RemoteError::FileNotFound { .. } => "file_not_found",
            RemoteError::TransferInterrupted { .. } => "transfer_interrupted",
            RemoteError::Cancelled => "cancelled",
            RemoteError::LocalIo { .. } => "local_io",
            RemoteError::CommandFailed { .. } => "command_failed",
            RemoteError::SessionLost { .. } => "session_lost",
            RemoteError::InvalidConfig { .. } => "invalid_config",
        }
    }

    pub(crate) fn local_io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        RemoteError::LocalIo {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid_config(detail: impl Into<String>) -> Self {
        RemoteError::InvalidConfig {
            detail: detail.into(),
        }
    }
}

/// Raccourci pour les résultats de la crate.
pub type Result<T> = std::result::Result<T, RemoteError>;

use logano_core::CoreError;
use logano_remote::RemoteError;
use serde::Serialize;
use specta::Type;

/// Erreur rendue à l'interface : un code stable, un message clair, un détail éventuel
/// (fichier de clé pour une phrase de passe, serveur pour sudo).
#[derive(Debug, Clone, Serialize, Type)]
pub struct AppError {
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
}

impl AppError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        AppError { code: code.to_string(), message: message.into(), detail: None }
    }
}

impl From<RemoteError> for AppError {
    fn from(e: RemoteError) -> Self {
        let detail = match &e {
            RemoteError::KeyPassphraseRequired { identity_file } | RemoteError::KeyPassphraseInvalid { identity_file } => Some(identity_file.clone()),
            _ => None,
        };
        AppError { code: e.code().to_string(), message: e.to_string(), detail }
    }
}

impl From<CoreError> for AppError {
    fn from(e: CoreError) -> Self {
        let code = match &e {
            CoreError::Cancelled => "cancelled",
            CoreError::FormatUnavailable(_) => "format_unavailable",
            CoreError::TemplateNotFound(_) => "template_not_found",
            _ => "core",
        };
        AppError::new(code, e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::new("local_io", format!("erreur disque : {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;

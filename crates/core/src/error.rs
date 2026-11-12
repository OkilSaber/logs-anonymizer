use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("template « {id} » : {msg}")]
    Template { id: String, msg: String },
    #[error("template « {0} » introuvable dans la bibliothèque")]
    TemplateNotFound(String),
    #[error("template « {id} » : le parent « {parent} » est introuvable ou sa version ne satisfait pas la contrainte")]
    ParentMissing { id: String, parent: String },
    #[error("template « {0} » : héritage cyclique")]
    InheritanceCycle(String),
    #[error("TOML invalide : {0}")]
    Toml(String),
    #[error("le format « {0} » n'est pas encore disponible dans cette version du moteur")]
    FormatUnavailable(String),
    #[error("lecture impossible : {0}")]
    Io(#[from] std::io::Error),
    #[error("fichier compressé tronqué ou corrompu : {0}")]
    Corrupt(String),
    #[error("traitement annulé")]
    Cancelled,
}

impl CoreError {
    pub fn template(id: &str, msg: impl Into<String>) -> Self {
        CoreError::Template { id: id.to_string(), msg: msg.into() }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

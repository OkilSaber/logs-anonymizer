//! Sortie anonymisée.
//!
//! [`Sanitized`] ne peut être construit que par le moteur, après le passage du filet de
//! sécurité. Tout ce qui écrit une sortie (fichier, presse-papier) ne prend que ce type :
//! du texte brut ne peut pas s'y glisser par erreur.

use crate::detect::DetectorId;
use crate::strategy::{Action, Normalize};

#[derive(Debug, Default)]
pub struct Sanitized(Vec<u8>);

impl Sanitized {
    pub(crate) fn seal(bytes: Vec<u8>) -> Self {
        Sanitized(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Remplacement appliqué par le filet de sécurité à ce qu'aucune règle n'a couvert.
pub fn default_action(d: DetectorId) -> Action {
    let redact = |label: &str| Action::Redact { label: label.to_string(), preserve_scheme: false };
    match d {
        DetectorId::Email => Action::Pseudonymize { token: "EMAIL".into(), normalize: Normalize::Email },
        DetectorId::Ipv4Public | DetectorId::Ipv6Public => Action::Pseudonymize { token: "IP".into(), normalize: Normalize::Ip },
        DetectorId::Phone => Action::Pseudonymize { token: "PHONE".into(), normalize: Normalize::Digits },
        DetectorId::BasicAuth | DetectorId::BearerToken | DetectorId::UrlUserinfo | DetectorId::CredentialAssignment => redact("CREDENTIALS"),
        DetectorId::Jwt => redact("JWT"),
        DetectorId::Iban => redact("IBAN"),
        DetectorId::CardLuhn => redact("CARD"),
        DetectorId::HighEntropy => redact("SECRET"),
    }
}

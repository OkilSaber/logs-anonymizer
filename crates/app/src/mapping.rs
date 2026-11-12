//! Table de correspondance jeton → valeur réelle d'un run. Elle sert à remettre les
//! vraies valeurs dans la réponse d'une IA. Optionnelle, gardée localement, chiffrée
//! (XChaCha20-Poly1305) avec une clé rangée dans le trousseau du système, jamais sur le
//! disque. Purgeable.

use crate::dto::{Deanonymized, MappingInfo};
use crate::error::{AppError, AppResult};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SERVICE: &str = "fr.kbrw.logs-anonymizer";
const ACCOUNT: &str = "mapping-key";
const MAGIC: &[u8; 8] = b"LOGAMAP1";

fn crypto_error() -> AppError {
    AppError::new("mapping", "Table de correspondance illisible : fichier abîmé, ou clé du trousseau différente de celle qui l'a chiffrée.")
}

/// Clé de chiffrement des tables : lue dans le trousseau, créée au premier usage.
pub fn keychain_key() -> AppResult<[u8; 32]> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let unavailable = |e: keyring::Error| AppError::new("keychain", format!("Trousseau indisponible : {e}. La table de correspondance n'est pas enregistrée."));
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(unavailable)?;
    match entry.get_password() {
        Ok(stored) => {
            let bytes = b64.decode(stored.trim()).map_err(|_| crypto_error())?;
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| crypto_error())
        }
        Err(keyring::Error::NoEntry) => {
            let key: [u8; 32] = rand::random();
            entry.set_password(&b64.encode(key)).map_err(unavailable)?;
            Ok(key)
        }
        Err(e) => Err(unavailable(e)),
    }
}

fn file_for(dir: &Path, run_id: &str) -> AppResult<PathBuf> {
    if run_id.is_empty() || !run_id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        return Err(AppError::new("mapping", "Identifiant de run invalide."));
    }
    Ok(dir.join(format!("{run_id}.map")))
}

/// Chiffre et enregistre la table d'un run. Rend le nombre de jetons.
pub fn save(dir: &Path, key: &[u8; 32], run_id: &str, pairs: &[(String, String)]) -> AppResult<u64> {
    let path = file_for(dir, run_id)?;
    std::fs::create_dir_all(dir)?;
    let plain = serde_json::to_vec(pairs).map_err(|e| AppError::new("mapping", e.to_string()))?;
    let nonce: [u8; 24] = rand::random();
    let cipher = XChaCha20Poly1305::new(key.into());
    let sealed = cipher.encrypt(XNonce::from_slice(&nonce), plain.as_slice()).map_err(|_| crypto_error())?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + nonce.len() + sealed.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&sealed);
    let tmp = path.with_extension("map.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(pairs.len() as u64)
}

pub fn load(dir: &Path, key: &[u8; 32], run_id: &str) -> AppResult<HashMap<String, String>> {
    let bytes = std::fs::read(file_for(dir, run_id)?).map_err(|_| AppError::new("mapping", "Ce run n'a pas de table de correspondance."))?;
    if bytes.len() < MAGIC.len() + 24 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(crypto_error());
    }
    let (nonce, sealed) = bytes[MAGIC.len()..].split_at(24);
    let plain = XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(nonce), sealed).map_err(|_| crypto_error())?;
    let pairs: Vec<(String, String)> = serde_json::from_slice(&plain).map_err(|_| crypto_error())?;
    Ok(pairs.into_iter().collect())
}

/// Tables présentes, de la plus récente à la plus ancienne. Ne déchiffre rien.
pub fn list(dir: &Path) -> Vec<MappingInfo> {
    let mut infos: Vec<(std::time::SystemTime, MappingInfo)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let run_id = path.file_name()?.to_str()?.strip_suffix(".map")?.to_string();
            let meta = e.metadata().ok()?;
            Some((meta.modified().ok()?, MappingInfo { run_id, bytes: meta.len() }))
        })
        .collect();
    infos.sort_by_key(|info| std::cmp::Reverse(info.0));
    infos.into_iter().map(|(_, i)| i).collect()
}

/// Supprime une table, ou toutes si `run_id` est `None`.
pub fn purge(dir: &Path, run_id: Option<&str>) -> AppResult<()> {
    match run_id {
        Some(id) => match std::fs::remove_file(file_for(dir, id)?) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        },
        None => {
            for info in list(dir) {
                let _ = std::fs::remove_file(dir.join(format!("{}.map", info.run_id)));
            }
            Ok(())
        }
    }
}

/// Remplace chaque jeton connu (`EMAIL_7f3a2c9d`) par sa valeur réelle. Les jetons inconnus
/// de cette table sont laissés tels quels et comptés.
pub fn deanonymize(text: &str, table: &HashMap<String, String>) -> Deanonymized {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut replaced, mut unknown) = (0u64, 0u64);
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if boundary && bytes[i].is_ascii_uppercase() {
            // LABEL en majuscules et chiffres, `_`, puis au moins 8 chiffres hexadécimaux.
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit()) {
                j += 1;
            }
            if bytes.get(j) == Some(&b'_') {
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k].is_ascii_digit() || (b'a'..=b'f').contains(&bytes[k])) {
                    k += 1;
                }
                let ends = !bytes.get(k).is_some_and(|b| b.is_ascii_alphanumeric());
                if k - (j + 1) >= 8 && ends {
                    match table.get(&text[i..k]) {
                        Some(real) => {
                            out.push_str(&text[copied..i]);
                            out.push_str(real);
                            copied = k;
                            replaced += 1;
                        }
                        None => unknown += 1,
                    }
                    i = k;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    Deanonymized { text: out, replaced, unknown }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("logano-mapping-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_table_round_trips_encrypted_and_only_with_its_key() {
        let d = dir("roundtrip");
        let pairs = vec![("EMAIL_e3236363".to_string(), "jean.dupont@example.com".to_string()), ("NAME_af515ce0".to_string(), "DUPONT".to_string())];
        assert_eq!(save(&d, &[7; 32], "20261111-005749-etam-2026-10-01", &pairs).unwrap(), 2);
        let table = load(&d, &[7; 32], "20261111-005749-etam-2026-10-01").unwrap();
        assert_eq!(table["EMAIL_e3236363"], "jean.dupont@example.com");
        // Sur le disque : rien de lisible.
        let raw = std::fs::read(d.join("20261111-005749-etam-2026-10-01.map")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"DUPONT") && !raw.windows(5).any(|w| w == b"EMAIL"));
        // Mauvaise clé, fichier modifié, run inconnu, identifiant douteux : erreurs claires.
        assert_eq!(load(&d, &[8; 32], "20261111-005749-etam-2026-10-01").unwrap_err().code, "mapping");
        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        std::fs::write(d.join("x.map"), tampered).unwrap();
        assert!(load(&d, &[7; 32], "x").is_err());
        assert!(load(&d, &[7; 32], "absent").is_err());
        assert!(load(&d, &[7; 32], "../evil").is_err());

        assert_eq!(list(&d).len(), 2);
        purge(&d, Some("x")).unwrap();
        assert_eq!(list(&d).iter().map(|i| i.run_id.as_str()).collect::<Vec<_>>(), vec!["20261111-005749-etam-2026-10-01"]);
        purge(&d, None).unwrap();
        assert!(list(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn tokens_are_replaced_by_their_real_value() {
        let table: HashMap<String, String> =
            [("EMAIL_e3236363", "jean.dupont@example.com"), ("IP_ad3bba6c", "203.0.113.10"), ("NAME_af515ce0aa", "Dupont")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let r = deanonymize("Le compte EMAIL_e3236363 (NAME_af515ce0aa) s'est connecté depuis IP_ad3bba6c, puis EMAIL_00000000 aussi. « EMAIL_e3236363 ».", &table);
        assert_eq!(r.text, "Le compte jean.dupont@example.com (Dupont) s'est connecté depuis 203.0.113.10, puis EMAIL_00000000 aussi. « jean.dupont@example.com ».");
        assert_eq!((r.replaced, r.unknown), (4, 1));
        // Ce qui ressemble à un jeton sans en être un n'est pas touché.
        let r = deanonymize("ETAM_0063 XEMAIL_e3236363 EMAIL_e32 EMAIL_e3236363z [EMAIL] email_e3236363", &table);
        assert_eq!((r.text.as_str(), r.replaced), ("ETAM_0063 XEMAIL_e3236363 EMAIL_e32 EMAIL_e3236363z [EMAIL] email_e3236363", 0));
    }
}

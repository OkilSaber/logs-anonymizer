//! Magasin TOFU des empreintes de clés d'hôte (fichier JSON propre à l'app).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Sérialise les lectures-écritures du fichier entre connexions simultanées.
static STORE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KnownHost {
    algorithm: String,
    fingerprint: String,
    first_seen: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    #[serde(default)]
    hosts: BTreeMap<String, KnownHost>,
}

pub(crate) enum Verdict {
    /// Empreinte déjà connue et identique, ou enregistrée à l'instant.
    Trusted,
    /// Empreinte différente de celle enregistrée.
    Changed { expected: String },
}

/// Compare l'empreinte à celle du fichier ; l'enregistre au premier contact.
pub(crate) fn check_or_record(
    path: &Path,
    host: &str,
    port: u16,
    algorithm: &str,
    fingerprint: &str,
) -> std::io::Result<Verdict> {
    let _guard = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = load(path)?;
    let key = format!("{host}:{port}");
    if let Some(known) = store.hosts.get(&key) {
        return Ok(if known.fingerprint == fingerprint {
            Verdict::Trusted
        } else {
            Verdict::Changed {
                expected: known.fingerprint.clone(),
            }
        });
    }
    store.hosts.insert(
        key,
        KnownHost {
            algorithm: algorithm.to_string(),
            fingerprint: fingerprint.to_string(),
            first_seen: chrono::Utc::now().to_rfc3339(),
        },
    );
    save(path, &store)?;
    Ok(Verdict::Trusted)
}

fn load(path: &Path) -> std::io::Result<Store> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok(Store::default()),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
        Err(e) => Err(e),
    }
}

fn save(path: &Path, store: &Store) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let json = serde_json::to_vec_pretty(store).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn premier_contact_puis_changement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sous/known_hosts.json");
        assert!(matches!(
            check_or_record(&path, "h", 22, "ssh-ed25519", "SHA256:aaa").unwrap(),
            Verdict::Trusted
        ));
        assert!(matches!(
            check_or_record(&path, "h", 22, "ssh-ed25519", "SHA256:aaa").unwrap(),
            Verdict::Trusted
        ));
        match check_or_record(&path, "h", 22, "ssh-ed25519", "SHA256:bbb").unwrap() {
            Verdict::Changed { expected } => assert_eq!(expected, "SHA256:aaa"),
            Verdict::Trusted => panic!("le changement de clé doit être détecté"),
        }
        // Un autre port est un autre hôte.
        assert!(matches!(
            check_or_record(&path, "h", 2222, "ssh-ed25519", "SHA256:bbb").unwrap(),
            Verdict::Trusted
        ));
    }
}

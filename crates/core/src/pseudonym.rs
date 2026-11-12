//! Jetons déterministes : `EMAIL_7f3a2c9d`.
//!
//! `HMAC-SHA256(clé du run, TOKEN | 0x1F | valeur normalisée)`, 8 hex par défaut. Pas de
//! compteur partagé : le même couple (clé, valeur) donne le même jeton sur n'importe quel
//! thread. Un registre concurrent ne sert qu'à détecter les collisions.

use dashmap::mapref::entry::Entry as MapEntry;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const BASE_HEX: usize = 8;

pub struct Pseudonymizer {
    key: [u8; 32],
    /// Jeton → empreinte de la valeur qui l'a obtenu.
    registry: DashMap<String, [u8; 8]>,
    /// Jeton → valeur d'origine, si la table de correspondance est demandée.
    mapping: Option<DashMap<String, String>>,
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

impl Pseudonymizer {
    pub fn new(key: [u8; 32], collect_mapping: bool) -> Self {
        Pseudonymizer { key, registry: DashMap::new(), mapping: collect_mapping.then(DashMap::new) }
    }

    /// Écrit le jeton de `normalized` (valeur d'origine `original`) dans `out`.
    pub fn token(&self, label: &str, normalized: &[u8], original: &[u8], out: &mut Vec<u8>) {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepte toute taille de clé");
        mac.update(label.as_bytes());
        mac.update(&[0x1f]);
        mac.update(normalized);
        let digest = mac.finalize().into_bytes();
        let digits = hex(&digest[..16]);
        let mut fp = [0u8; 8];
        fp.copy_from_slice(&digest[24..32]);

        let mut len = BASE_HEX;
        let token = loop {
            let candidate = format!("{label}_{}", &digits[..len]);
            match self.registry.entry(candidate.clone()) {
                MapEntry::Vacant(v) => {
                    v.insert(fp);
                    break candidate;
                }
                MapEntry::Occupied(o) if *o.get() == fp || len >= digits.len() => break candidate,
                // Collision : une autre valeur porte déjà ce jeton, on l'allonge.
                MapEntry::Occupied(_) => len += 2,
            }
        };
        if let Some(map) = &self.mapping {
            map.entry(token.clone()).or_insert_with(|| String::from_utf8_lossy(original).into_owned());
        }
        out.extend_from_slice(token.as_bytes());
    }

    /// Table jeton → valeur d'origine (vide si elle n'a pas été demandée).
    pub fn mapping(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self.mapping.iter().flat_map(|m| m.iter().map(|e| (e.key().clone(), e.value().clone())).collect::<Vec<_>>()).collect();
        v.sort();
        v
    }

    #[cfg(test)]
    fn force_collision(&self, token: &str) {
        self.registry.insert(token.to_string(), [0xAA; 8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(p: &Pseudonymizer, label: &str, v: &str) -> String {
        let mut out = Vec::new();
        p.token(label, v.as_bytes(), v.as_bytes(), &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn deterministic_typed_and_keyed() {
        let p = Pseudonymizer::new([7; 32], false);
        let a = tok(&p, "EMAIL", "jean.dupont@example.com");
        assert!(a.starts_with("EMAIL_") && a.len() == 6 + 8, "{a}");
        assert_eq!(a, tok(&p, "EMAIL", "jean.dupont@example.com"));
        assert_ne!(a, tok(&p, "EMAIL", "a.martin@example.com"));
        assert_ne!(a[6..], tok(&p, "USER", "jean.dupont@example.com")[5..]);
        // Autre clé de run : autres jetons.
        assert_ne!(a, tok(&Pseudonymizer::new([8; 32], false), "EMAIL", "jean.dupont@example.com"));
        // Même clé dans un autre run : mêmes jetons.
        assert_eq!(a, tok(&Pseudonymizer::new([7; 32], false), "EMAIL", "jean.dupont@example.com"));
    }

    #[test]
    fn collision_extends_the_token() {
        let p = Pseudonymizer::new([7; 32], true);
        let normal = tok(&Pseudonymizer::new([7; 32], false), "EMAIL", "x@example.com");
        p.force_collision(&normal);
        let extended = tok(&p, "EMAIL", "x@example.com");
        assert_eq!(extended.len(), normal.len() + 2);
        assert!(extended.starts_with(&normal));
        assert_eq!(extended, tok(&p, "EMAIL", "x@example.com"));
        assert_eq!(p.mapping(), vec![(extended, "x@example.com".to_string())]);
    }
}

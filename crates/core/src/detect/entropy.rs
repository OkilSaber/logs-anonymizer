//! Chaînes base64 ou hexadécimales longues à forte entropie (secrets, signatures).

use super::{push, DetectorConfig, DetectorId, Finding};

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

fn shannon(t: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    for &b in t {
        counts[b as usize] += 1;
    }
    let n = t.len() as f32;
    counts.iter().filter(|c| **c > 0).map(|&c| {
        let p = c as f32 / n;
        -p * p.log2()
    }).sum()
}

/// Part des caractères alphanumériques qui changent de classe (minuscule, majuscule,
/// chiffre) par rapport au précédent. Une chaîne aléatoire tourne autour de 0,6 ; un
/// identifiant (`ConfirmationCommande2`) ou un nom de fichier daté reste sous 0,3.
fn class_changes(t: &[u8]) -> f32 {
    let class = |b: u8| if b.is_ascii_lowercase() { 0 } else if b.is_ascii_uppercase() { 1 } else { 2 };
    let mut prev = None;
    let (mut changes, mut n) = (0u32, 0u32);
    for &b in t.iter().filter(|b| b.is_ascii_alphanumeric()) {
        let c = class(b);
        if prev.is_some_and(|p| p != c) {
            changes += 1;
        }
        prev = Some(c);
        n += 1;
    }
    if n < 2 { 0.0 } else { changes as f32 / (n - 1) as f32 }
}

/// Part des caractères alphanumériques qui appartiennent à des mots : une suite d'au moins
/// 4 lettres contenant une voyelle, en casse de mot (`retard`, `Retard`, `RETARD`).
/// `RetardPreparationMagasin_CnC2h` est fait de mots à 80 % ; une clé aléatoire, presque pas.
fn word_fraction(t: &[u8]) -> f32 {
    let is_word = |w: &[u8]| {
        let uppers = w.iter().take_while(|b| b.is_ascii_uppercase()).count();
        let lower_tail = w[uppers..].iter().all(u8::is_ascii_lowercase);
        let cased = lower_tail && (uppers <= 1 || uppers == w.len());
        w.len() >= 4 && cased && w.iter().any(|b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u' | b'y'))
    };
    let mut in_words = 0usize;
    let mut start = 0;
    for i in 0..=t.len() {
        // Un mot s'arrête sur un non-lettre, et avant une majuscule qui suit une minuscule.
        let boundary = i == t.len() || !t[i].is_ascii_alphabetic() || (i > start && t[i].is_ascii_uppercase() && t[i - 1].is_ascii_lowercase());
        if !boundary {
            continue;
        }
        if i > start && is_word(&t[start..i]) {
            in_words += i - start;
        }
        start = if i < t.len() && t[i].is_ascii_alphabetic() { i } else { i + 1 };
    }
    let alnum = t.iter().filter(|b| b.is_ascii_alphanumeric()).count();
    if alnum == 0 { 0.0 } else { in_words as f32 / alnum as f32 }
}

/// Un chemin : la moitié au moins de ses caractères sont dans des segments ordinaires
/// (courts, sans mélange de casse, ou faits de mots). Les segments d'une clé en base64
/// mélangent minuscules et majuscules sans former de mots.
fn path_like(t: &[u8]) -> bool {
    let (mut ordinary, mut total) = (0usize, 0usize);
    for piece in t.split(|b| *b == b'/') {
        let n = piece.iter().filter(|b| b.is_ascii_alphanumeric()).count();
        total += n;
        let mixed = piece.iter().any(u8::is_ascii_lowercase) && piece.iter().any(u8::is_ascii_uppercase);
        if !mixed || piece.len() < 6 || word_fraction(piece) >= 0.5 {
            ordinary += n;
        }
    }
    total > 0 && ordinary * 2 >= total
}

/// Un secret plausible : hexadécimal long mêlant chiffres et lettres, ou base64 mêlant
/// minuscules, majuscules et chiffres. Les suites de chiffres seuls, les identifiants
/// en minuscules et les constantes en majuscules n'en sont pas.
fn secret_like(t: &[u8], cfg: &DetectorConfig) -> bool {
    let lower = t.iter().any(u8::is_ascii_lowercase);
    let upper = t.iter().any(u8::is_ascii_uppercase);
    let digit = t.iter().any(u8::is_ascii_digit);
    if t.iter().all(u8::is_ascii_hexdigit) {
        return t.len() >= 32 && digit && (lower || upper) && shannon(t) >= 3.0;
    }
    lower && upper && digit && shannon(t) >= cfg.entropy_min_bits && class_changes(t) >= 0.35 && word_fraction(t) < 0.5
}

pub fn high_entropy(h: &[u8], cfg: &DetectorConfig, out: &mut Vec<Finding>) {
    let mut i = 0;
    while i < h.len() {
        if !is_token(h[i]) {
            i += 1;
            continue;
        }
        let mut s = i;
        while i < h.len() && is_token(h[i]) {
            i += 1;
        }
        // `%7C…` : les deux chiffres hexadécimaux appartiennent à l'encodage URL.
        if s > 0 && h[s - 1] == b'%' && i - s >= 2 && h[s].is_ascii_hexdigit() && h[s + 1].is_ascii_hexdigit() {
            s += 2;
        }
        let core = &h[s..i];
        let mut e = i;
        while e < h.len() && h[e] == b'=' && e - i < 2 {
            e += 1;
        }
        i = e;
        if core.len() < cfg.entropy_min_len {
            continue;
        }
        // Un chemin (`PREPROD/ECOM/ORDERS/fichier_2026…`) n'est pas un secret, mais une clé en
        // base64 peut contenir des `/` : on ne l'écarte que si elle ressemble à un chemin.
        let hit = secret_like(core, cfg) && !(core.contains(&b'/') && path_like(core));
        if hit {
            push(out, s, e, DetectorId::HighEntropy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::found;
    use super::super::DetectorId::*;

    #[test]
    fn secrets() {
        assert_eq!(found(HighEntropy, "%7C1794217138%7CAbCdEfGhIjKlMnOpQrStUvWxYz0="), vec!["AbCdEfGhIjKlMnOpQrStUvWxYz0="]);
        assert_eq!(found(HighEntropy, "sha=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08."), vec!["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]);
        assert_eq!(found(HighEntropy, "key Zm9vYmFy/MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA== end"), vec!["Zm9vYmFy/MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA=="]);
    }

    use super::word_fraction;

    #[test]
    fn word_fractions() {
        assert!(word_fraction(b"RetardPreparationMagasin_CnC2h") > 0.75);
        assert!(word_fraction(b"sfcc_ETAM_20261105T041500_DeltaExportOffers") > 0.5);
        assert!(word_fraction(b"AbCdEfGhIjKlMnOpQrStUvWxYz0") < 0.1);
        assert!(word_fraction(b"dXNlcjpwYXNzd29yZA") < 0.3);
    }

    /// Des clés aléatoires en base64 : elles doivent presque toutes rester détectées, même
    /// avec le critère des mots (une clé peut contenir un mot par hasard).
    #[test]
    fn random_base64_keys_are_still_detected() {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut seed = 0x9E3779B97F4A7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let (mut total, mut detected) = (0, 0);
        for len in [24usize, 28, 32, 40, 44, 64, 88] {
            for _ in 0..600 {
                let key: String = (0..len).map(|_| ALPHABET[(next() % 64) as usize] as char).collect();
                // Les rares tirages sans les trois classes de caractères ne sont pas des cas à détecter.
                if !(key.bytes().any(|b| b.is_ascii_lowercase()) && key.bytes().any(|b| b.is_ascii_uppercase()) && key.bytes().any(|b| b.is_ascii_digit())) {
                    continue;
                }
                total += 1;
                if !found(HighEntropy, &format!("key={key} end")).is_empty() {
                    detected += 1;
                }
            }
        }
        assert!(total > 4000);
        assert!(detected as f64 / total as f64 > 0.985, "{detected} détectées sur {total}");
    }

    #[test]
    fn paths_and_keys_with_slashes() {
        use super::path_like;
        for path in ["PREPROD/ECOM/ORDERS/sfcc_orders_2026101315150683", "data/delta_archive/sfcc_ETAM_20261105T041500_DeltaExportOffers", "lib/oms/Api/EWMApiSupEmails_transac", "api/gateway/store/42/preparation_list"] {
            assert!(path_like(path.as_bytes()), "{path}");
        }
        for key in ["Zm9vYmFy/MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA", "aB3dE6gH9/jK2mN5pQ8sT1vW", "x7Kp2Lm9Qw/4Rt6Yz1Bn8Vc3"] {
            assert!(!path_like(key.as_bytes()), "{key}");
            assert_eq!(found(HighEntropy, &format!("key {key} end")).len(), 1, "{key}");
        }
    }

    #[test]
    fn not_secrets() {
        for h in [
            "Error processing PREPROD/ECOM/ORDERS/sfcc_orders_2026101315150683.xml in oms_puller_ecom_orders_etam:",
            "/var/lib/riak/bitcask/816379690540573744318936321414700340018671616/189860.bitcask.data",
            "node-public_ipv4-188_165_78_170-443~ tls[TLSv1.3/TLS_CHACHA20_POLY1305_SHA256/26]",
            "#Reference<0.1590975473.2172125185.81270> etam_sb_order_audits XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "550e8400-e29b-41d4-a716-446655440000 lib/oms/riak/riak.ex:211: Riak.get/3",
            "custom_user_status:to_print_plaque%20AND%20custom_garage_id:000000E",
            // Noms de modèles d'email : des mots, un suffixe court avec un chiffre.
            "[EMAILS TRANSACS] schedule 211492773 (RetardPreparationMagasin_CnC2h) {{2026, 11, 1}, {0, 0, 0}}",
            "scheduled (ColisArriveEnAgence_V2bis) (CommandeComplete_Web3x) (RetardExpedition_H24Cnc)",
            "handleOAuth2CallbackRequestV2 parseHTTP2FrameHeader getUserByEmailV3Async",
            // Identifiants en CamelCase avec chiffres, noms de fichiers datés.
            "[EMAILS TRANSACS] scheduled 900000001 (ConfirmationCommandeClickAndCollect2) under key",
            "File generated is data/delta_archive/sfcc_ETAM_20261105T041500_DeltaExportOffers.csv",
            "path -> \"data/full_archive/full_UNDIZ_partner_20261105_041500_FullExport.csv\"",
        ] {
            assert!(found(HighEntropy, h).is_empty(), "faux positif dans : {h}");
        }
    }
}

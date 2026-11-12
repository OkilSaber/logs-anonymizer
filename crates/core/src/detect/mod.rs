//! Détecteurs intégrés : repèrent des données sensibles dans du texte libre.
//!
//! Chacun commence par un préfiltre littéral (`memchr`/`memmem`) et ne fait le travail
//! coûteux qu'autour des occurrences.

mod creds;
mod entropy;
mod ip;
mod numbers;

use memchr::{memchr_iter, memrchr};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DetectorId {
    Email,
    BasicAuth,
    BearerToken,
    Jwt,
    UrlUserinfo,
    /// `password: '…'`, `token=…`, `"secret" => "…"` dans du texte libre.
    CredentialAssignment,
    Ipv4Public,
    Ipv6Public,
    Phone,
    Iban,
    CardLuhn,
    HighEntropy,
}

impl DetectorId {
    pub const ALL: [DetectorId; 12] = [
        DetectorId::Email,
        DetectorId::BasicAuth,
        DetectorId::BearerToken,
        DetectorId::Jwt,
        DetectorId::UrlUserinfo,
        DetectorId::CredentialAssignment,
        DetectorId::Ipv4Public,
        DetectorId::Ipv6Public,
        DetectorId::Phone,
        DetectorId::Iban,
        DetectorId::CardLuhn,
        DetectorId::HighEntropy,
    ];

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|d| *d == self).expect("détecteur listé")
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DetectorId::Email => "email",
            DetectorId::BasicAuth => "basic_auth",
            DetectorId::BearerToken => "bearer_token",
            DetectorId::Jwt => "jwt",
            DetectorId::UrlUserinfo => "url_userinfo",
            DetectorId::CredentialAssignment => "credential_assignment",
            DetectorId::Ipv4Public => "ipv4_public",
            DetectorId::Ipv6Public => "ipv6_public",
            DetectorId::Phone => "phone",
            DetectorId::Iban => "iban",
            DetectorId::CardLuhn => "card_luhn",
            DetectorId::HighEntropy => "high_entropy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == s)
    }

    /// Détecteurs à faux positifs : une stratégie `keep` en protège une valeur.
    /// Les autres classes sont certaines et ne sont jamais exemptées par `keep`.
    pub fn weak(self) -> bool {
        matches!(self, DetectorId::Phone | DetectorId::CardLuhn | DetectorId::HighEntropy)
    }

    pub fn is_ip(self) -> bool {
        matches!(self, DetectorId::Ipv4Public | DetectorId::Ipv6Public)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub start: u32,
    pub end: u32,
    pub detector: DetectorId,
}

/// Réglages des détecteurs (section `[detectors.*]` d'un template).
#[derive(Clone, Copy, Debug)]
pub struct DetectorConfig {
    pub entropy_min_len: usize,
    pub entropy_min_bits: f32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig { entropy_min_len: 24, entropy_min_bits: 3.5 }
    }
}

pub(crate) fn push(out: &mut Vec<Finding>, start: usize, end: usize, detector: DetectorId) {
    if end > start {
        out.push(Finding { start: start as u32, end: end as u32, detector });
    }
}

pub(crate) fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Lance un détecteur sur `hay` et ajoute ses trouvailles à `out`.
pub fn detect(id: DetectorId, hay: &[u8], cfg: &DetectorConfig, out: &mut Vec<Finding>) {
    match id {
        DetectorId::Email => email(hay, out),
        DetectorId::BasicAuth => creds::basic(hay, out),
        DetectorId::BearerToken => creds::bearer(hay, out),
        DetectorId::Jwt => creds::jwt(hay, out),
        DetectorId::UrlUserinfo => creds::url_userinfo(hay, out),
        DetectorId::CredentialAssignment => creds::assignment(hay, out),
        DetectorId::Ipv4Public => ip::v4(hay, out),
        DetectorId::Ipv6Public => ip::v6(hay, out),
        DetectorId::Phone => numbers::phone(hay, out),
        DetectorId::Iban => numbers::iban(hay, out),
        DetectorId::CardLuhn => numbers::card(hay, out),
        DetectorId::HighEntropy => entropy::high_entropy(hay, cfg, out),
    }
}

fn is_local(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')
}

fn is_domain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// `local@domaine.tld`. Le `%` n'est pas admis dans la partie locale : un email
/// URL-encodé (`%40`) relève des vues décodées.
fn email(h: &[u8], out: &mut Vec<Finding>) {
    for at in memchr_iter(b'@', h) {
        let mut s = at;
        while s > 0 && is_local(h[s - 1]) && at - s < 64 {
            s -= 1;
        }
        while s < at && matches!(h[s], b'.' | b'-' | b'+') {
            s += 1;
        }
        if s == at {
            continue;
        }
        let mut e = at + 1;
        while e < h.len() && is_domain(h[e]) && e - at < 255 {
            e += 1;
        }
        while e > at + 1 && matches!(h[e - 1], b'.' | b'-') {
            e -= 1;
        }
        let dom = &h[at + 1..e];
        let Some(dot) = memrchr(b'.', dom) else { continue };
        let tld = &dom[dot + 1..];
        if dot == 0 || tld.len() < 2 || !tld.iter().all(u8::is_ascii_alphabetic) || memchr::memmem::find(dom, b"..").is_some() {
            continue;
        }
        push(out, s, e, DetectorId::Email);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn found(id: DetectorId, hay: &str) -> Vec<&str> {
        let mut out = Vec::new();
        detect(id, hay.as_bytes(), &DetectorConfig::default(), &mut out);
        out.iter().map(|f| &hay[f.start as usize..f.end as usize]).collect()
    }

    #[test]
    fn emails() {
        let f = |h| found(DetectorId::Email, h);
        assert_eq!(f("cookie : etam_admin-auth=jean.dupont@example.com%7C1794217138%7CAbCd="), vec!["jean.dupont@example.com"]);
        assert_eq!(f("in GET //api/etam_admin/jean.dupont@example.com/login"), vec!["jean.dupont@example.com"]);
        assert_eq!(f("recipients: [\"a.martin@example.com\", \"b.durand@example.com\"]"), vec!["a.martin@example.com", "b.durand@example.com"]);
        assert_eq!(f("sender: \"jardiland+mailer@kbrw.fr\"."), vec!["jardiland+mailer@kbrw.fr"]);
        assert_eq!(f("<<\"JEAN.DUPONT@EXAMPLE.COM\">>"), vec!["JEAN.DUPONT@EXAMPLE.COM"]);
        assert_eq!(f("owner jean@example.com. Suite"), vec!["jean@example.com"]);
        // Nœud Erlang sur IPv6, valeur encodée, pas de TLD : rien.
        assert!(f("[services@2001:41d0:9a:a12:ba04:9500:0:1]").is_empty());
        assert!(f("beammetrics.gateway_in%402001%3A41d0").is_empty());
        assert!(f("user@localhost a @ b @@ x@.com").is_empty());
    }
}

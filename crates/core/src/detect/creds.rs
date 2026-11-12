//! Identifiants et jetons : Basic, Bearer, JWT, `login:mot_de_passe@` dans une URL.

use super::{push, DetectorId, Finding};
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use aho_corasick::AhoCorasick;
use memchr::memmem;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// Préfiltre : un nom de clé d'identifiant est-il présent, quelle que soit la casse ?
static ASSIGN_HINT: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(["pass", "pwd", "secret", "token", "apikey", "api_key", "api-key", "private_key", "private-key"])
        .expect("motifs littéraux")
});

/// `clé <séparateur> valeur`, la valeur étant entre guillemets, entre apostrophes (charlist
/// Erlang) ou nue. La clé peut porter un préfixe (`access_token`, `client_secret`, `x-api-key`).
static ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:^|[^A-Za-z0-9_])(?:[a-z0-9]+[_-])*"#,
        r#"(?:password|passwd|pwd|passphrase|secret[_-]key(?:[_-]base)?|secret|token|api[_-]?key|private[_-]key)"#,
        r#"["']?\s*(?:=>|[:=])\s*(?:~[a-z])?"#,
        r#"(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|([^\s,;&"'\])}]+))"#,
    ))
    .expect("regex valide")
});

const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

/// Décode `Basic <b64>` et vérifie qu'on obtient `login:mot_de_passe` imprimable.
pub(crate) fn decodes_to_credentials(b64: &[u8]) -> bool {
    B64.decode(b64).is_ok_and(|d| d.contains(&b':') && d.iter().all(|b| !b.is_ascii_control()))
}

/// `Basic <base64>` : la trouvaille couvre le base64 seul, le schéma est conservé.
pub fn basic(h: &[u8], out: &mut Vec<Finding>) {
    for needle in [&b"Basic "[..], b"basic "] {
        for pos in memmem::find_iter(h, needle) {
            if pos > 0 && h[pos - 1].is_ascii_alphanumeric() {
                continue;
            }
            let s = pos + needle.len();
            let mut e = s;
            while e < h.len() && is_b64(h[e]) {
                e += 1;
            }
            let n = e - s;
            // Un mot ordinaire après « Basic » (« Basic authentication ») ne se décode pas
            // en login:mot_de_passe ; au-delà de 24 caractères on ne prend pas le risque.
            if n >= 8 && (decodes_to_credentials(&h[s..e]) || n >= 24) {
                push(out, s, e, DetectorId::BasicAuth);
            }
        }
    }
}

/// `Bearer <jeton>` d'au moins 16 caractères.
pub fn bearer(h: &[u8], out: &mut Vec<Finding>) {
    for needle in [&b"Bearer "[..], b"bearer "] {
        for pos in memmem::find_iter(h, needle) {
            if pos > 0 && h[pos - 1].is_ascii_alphanumeric() {
                continue;
            }
            let s = pos + needle.len();
            let mut e = s;
            while e < h.len() && (h[e].is_ascii_alphanumeric() || matches!(h[e], b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')) {
                e += 1;
            }
            if e - s >= 16 {
                push(out, s, e, DetectorId::BearerToken);
            }
        }
    }
}

/// JWT : `eyJ….eyJ….signature`, en clair ou avec un padding URL-encodé (`%3D`).
pub fn jwt(h: &[u8], out: &mut Vec<Finding>) {
    let mut last_end = 0;
    for pos in memmem::find_iter(h, b"eyJ") {
        if pos < last_end || (pos > 0 && is_b64url(h[pos - 1])) {
            continue;
        }
        let mut i = pos;
        let mut dots = 0;
        let mut seg = 0usize;
        while i < h.len() {
            let c = h[i];
            if is_b64url(c) || c == b'=' {
                i += 1;
                seg += 1;
            } else if c == b'%' && h.get(i + 1) == Some(&b'3') && h.get(i + 2).is_some_and(|d| d | 0x20 == b'd') {
                i += 3;
                seg += 1;
            } else if c == b'.' && seg >= 4 && dots < 2 && h.get(i + 1).is_some_and(|n| is_b64url(*n)) {
                dots += 1;
                seg = 0;
                i += 1;
            } else {
                break;
            }
        }
        if dots >= 1 && i - pos >= 20 {
            push(out, pos, i, DetectorId::Jwt);
            last_end = i;
        }
    }
}

/// Valeur affectée à une clé d'identifiant dans du texte libre : `password: 'x'`,
/// `"password" => "x"`, `token=x`, `secret: "x"`. Indépendant de la structure du dump :
/// une liste keyword, un terme Erlang ou une query string donnent le même résultat.
pub fn assignment(h: &[u8], out: &mut Vec<Finding>) {
    if !ASSIGN_HINT.is_match(h) {
        return;
    }
    for caps in ASSIGN.captures_iter(h) {
        let (m, quoted) = match (caps.get(1), caps.get(2), caps.get(3)) {
            (Some(m), _, _) | (_, Some(m), _) => (m, true),
            (_, _, Some(m)) => (m, false),
            _ => continue,
        };
        let v = m.as_bytes();
        // Déjà masqué par l'application (`[FILTERED]`) ou par nous.
        let placeholder = v.len() >= 3 && v[0] == b'[' && v[v.len() - 1] == b']' && v[1..v.len() - 1].iter().all(|b| b.is_ascii_uppercase() || *b == b'_');
        if v.is_empty() || placeholder {
            continue;
        }
        if !quoted {
            // Une valeur nue n'est prise que si elle ressemble à un littéral : ni atome,
            // ni début de conteneur, ni mot-clé.
            let keyword = matches!(v, b"nil" | b"true" | b"false" | b"null" | b"undefined" | b"none");
            if v.len() < 4 || keyword || matches!(v[0], b'[' | b'%' | b'{' | b'#' | b':' | b'<' | b'&' | b'(') {
                continue;
            }
        }
        push(out, m.start(), m.end(), DetectorId::CredentialAssignment);
    }
}

/// `schéma://login:mot_de_passe@hôte` : la trouvaille couvre `login:mot_de_passe`.
pub fn url_userinfo(h: &[u8], out: &mut Vec<Finding>) {
    for pos in memmem::find_iter(h, b"://") {
        let s = pos + 3;
        let mut i = s;
        let mut colon = None;
        while i < h.len() && i - s < 256 {
            match h[i] {
                b'@' => {
                    if let Some(c) = colon {
                        if c > s && i > c + 1 {
                            push(out, s, i, DetectorId::UrlUserinfo);
                        }
                    }
                    break;
                }
                b':' if colon.is_none() => colon = Some(i),
                b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'[' | b']' => break,
                c if c.is_ascii_whitespace() => break,
                _ => {}
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::found;
    use super::super::DetectorId::*;

    #[test]
    fn basic_auth() {
        assert_eq!(found(BasicAuth, "\tauthorization : Basic dXNlcjpwYXNzd29yZA=="), vec!["dXNlcjpwYXNzd29yZA=="]);
        assert_eq!(found(BasicAuth, "\"authorization\" => \"Basic dXNlcjpwYXNzd29yZA==\","), vec!["dXNlcjpwYXNzd29yZA=="]);
        assert!(found(BasicAuth, "Basic authentication failed for realm").is_empty());
        assert!(found(BasicAuth, "Basic auth").is_empty());
        // Base64 long non décodable en login:mot_de_passe : pris quand même.
        assert_eq!(found(BasicAuth, "Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").len(), 1);
    }

    #[test]
    fn bearer_and_jwt() {
        assert_eq!(found(BearerToken, "authorization: Bearer abcDEF123456_-.xyz789"), vec!["abcDEF123456_-.xyz789"]);
        assert!(found(BearerToken, "Bearer token missing").is_empty());
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ4In0%3D.c2lnbmF0dXJl";
        assert_eq!(found(Jwt, &format!("client_assertion={jwt}&x=1")), vec![jwt]);
        assert_eq!(found(Jwt, "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123 next"), vec!["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123"]);
        assert!(found(Jwt, "eyJustAWordWithoutDots and keyJabc.def").is_empty());
    }

    #[test]
    fn credential_assignments() {
        let f = |h| found(CredentialAssignment, h);
        // Liste keyword Elixir avec charlists Erlang : la forme qui avait fui.
        assert_eq!(
            f("host: \"sftp.example.com\", opts.port: 222, connect_opts: [user: 'svc_demo', password: 'Xy*=7&gZtjHk?R', user_interaction: false]"),
            vec!["Xy*=7&gZtjHk?R"]
        );
        assert_eq!(f("%{\"password\" => \"s3cr3t, with } and \\\" inside\", \"user\" => \"x\"}"), vec!["s3cr3t, with } and \\\" inside"]);
        assert_eq!(f("POST /login?user=bob&password=hunter22&next=/"), vec!["hunter22"]);
        assert_eq!(f("client_secret: \"abc\", access_token=tok_1234567 X-Api-Key: k_998877"), vec!["abc", "tok_1234567", "k_998877"]);
        assert_eq!(f("PASSWORD = 'MiXed'  pwd: ~c\"legacy\"  secret_key_base: \"zzz\""), vec!["MiXed", "legacy", "zzz"]);
        // Rien à masquer : valeurs absentes, atomes, conteneurs, déjà filtrées, simple mention.
        assert!(f("password: nil, token: :undefined, secret: %{a: 1}, password: \"\", \"password\" => \"[FILTERED]\"").is_empty());
        assert!(f("An access_token was obtained ; invalid password for user ; tokens: 3 ; passwordless").is_empty());
        assert!(f("password: '[CREDENTIALS]' token=[CREDENTIALS]").is_empty());
    }

    #[test]
    fn url_credentials() {
        assert_eq!(found(UrlUserinfo, "GET https://admin:s3cret@partner.example.com/x"), vec!["admin:s3cret"]);
        assert!(found(UrlUserinfo, "http://host:8080/path?email=a@b.com").is_empty());
        assert!(found(UrlUserinfo, "http://[2001:db8::1]:80/ and user@host").is_empty());
    }
}

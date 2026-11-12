//! Quotage shell des arguments envoyés dans une commande distante.

/// Protège `s` pour un shell POSIX : tout est mis entre apostrophes, et chaque
/// apostrophe du texte devient `'\''`. Le résultat est toujours un seul mot,
/// quels que soient les espaces, `$`, `;`, retours à la ligne ou guillemets.
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Comme [`shell_quote`], mais laisse tel quel un mot fait uniquement de
/// caractères sans signification pour le shell (noms d'hôtes, ports).
pub(crate) fn shell_word(s: &str) -> String {
    let safe = !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/'));
    if safe {
        s.to_string()
    } else {
        shell_quote(s)
    }
}

/// Assemble `programme -- 'a' 'b'` à partir d'une liste de chemins.
pub(crate) fn quoted_list<S: AsRef<str>>(items: &[S]) -> String {
    items
        .iter()
        .map(|s| shell_quote(s.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_simple() {
        assert_eq!(shell_quote("/srv/syslog/a.log"), "'/srv/syslog/a.log'");
    }

    #[test]
    fn quote_apostrophe_et_metacaracteres() {
        assert_eq!(shell_quote("l'app"), "'l'\\''app'");
        assert_eq!(shell_quote("a b;rm -rf $HOME"), "'a b;rm -rf $HOME'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn word_laisse_les_hotes_intacts() {
        assert_eq!(
            shell_word("syslogserver01.priv.etamadm-sb.kbrw.fr"),
            "syslogserver01.priv.etamadm-sb.kbrw.fr"
        );
        assert_eq!(shell_word("a;b"), "'a;b'");
        assert_eq!(shell_word("-oProxyCommand=x"), "'-oProxyCommand=x'");
    }
}

//! `erlang.log` : Elixir Logger via syslog.
//!
//! Chaque ligne physique est `<host>␠␠<contenu>`. Une entrée commence par
//! `HH:MM:SS.mmm [level] message` ; les lignes suivantes de la même source sont ses
//! continuations, jusqu'à un séparateur, un nouveau début ou une ligne hors Logger.

use super::{frame_syslog, Format, FormatKind, Framed, LineClass};
use crate::entry::{EntryKind, Level};

pub struct ElixirSyslog;

/// `HH:MM:SS.mmm [level]` en tête de contenu → (niveau, position après le `]`).
pub fn parse_start(c: &[u8]) -> Option<(Level, usize)> {
    if c.len() < 16 {
        return None;
    }
    let d = |i: usize| c[i].is_ascii_digit();
    if !(d(0) && d(1) && c[2] == b':' && d(3) && d(4) && c[5] == b':' && d(6) && d(7) && c[8] == b'.' && d(9) && d(10) && d(11) && c[12] == b' ' && c[13] == b'[')
    {
        return None;
    }
    let close = memchr::memchr(b']', &c[14..c.len().min(14 + 12)])? + 14;
    let level = Level::parse(&c[14..close])?;
    Some((level, close + 1))
}

/// `nom:valeur|type[|…]`, sans espace : métrique statsd.
fn is_statsd(c: &[u8]) -> bool {
    if c.is_empty() || c.iter().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let Some(bar) = memchr::memchr(b'|', c) else { return false };
    let Some(colon) = memchr::memrchr(b':', &c[..bar]) else { return false };
    if colon == 0 {
        return false;
    }
    let value = &c[colon + 1..bar];
    if value.is_empty() || !value.iter().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+')) {
        return false;
    }
    let rest = &c[bar + 1..];
    let ty_end = memchr::memchr(b'|', rest).unwrap_or(rest.len());
    matches!(&rest[..ty_end], b"c" | b"g" | b"ms" | b"s" | b"h" | b"kv" | b"m")
}

/// `[YYYY-MM-DD ` en tête.
fn is_io_timestamp(c: &[u8]) -> bool {
    c.len() > 12
        && c[0] == b'['
        && c[1..5].iter().all(u8::is_ascii_digit)
        && c[5] == b'-'
        && c[6..8].iter().all(u8::is_ascii_digit)
        && c[8] == b'-'
        && c[9..11].iter().all(u8::is_ascii_digit)
        && c[11] == b' '
}

impl Format for ElixirSyslog {
    fn kind(&self) -> FormatKind {
        FormatKind::ElixirSyslog
    }

    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a> {
        frame_syslog(line)
    }

    fn classify(&self, c: &[u8]) -> LineClass {
        if c.iter().all(|b| b.is_ascii_whitespace()) {
            return LineClass::Separator;
        }
        if let Some((level, _)) = parse_start(c) {
            return LineClass::Start { level: Some(level) };
        }
        match c[0] {
            b'=' if c.starts_with(b"=====") => {
                let rest = c[5..].trim_ascii();
                if rest.is_empty() || rest.starts_with(b"ALIVE") {
                    LineClass::Standalone(EntryKind::Alive)
                } else if rest.starts_with(b"LOGGING STARTED") {
                    LineClass::Standalone(EntryKind::LoggingStarted)
                } else {
                    LineClass::Standalone(EntryKind::Other)
                }
            }
            b'[' if is_io_timestamp(c) => LineClass::Standalone(EntryKind::IoTimestamped),
            b'm' if c.starts_with(b"message repeated ") => LineClass::Standalone(EntryKind::Repeated),
            b'i' if c.starts_with(b"ignore event ") => LineClass::Standalone(EntryKind::Other),
            _ if is_statsd(c) => LineClass::Standalone(EntryKind::Statsd),
            _ => LineClass::Continuation,
        }
    }

    fn message_start(&self, header: &[u8]) -> usize {
        match parse_start(header) {
            Some((_, mut i)) => {
                while i < header.len() && header[i] == b' ' {
                    i += 1;
                }
                i
            }
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_on_first_double_space() {
        let f = ElixirSyslog.frame(b"etam-services01.etam-sb.kbrw.fr  00:00:02.032 [info]  in GET /api/ping");
        assert_eq!(f.source, b"etam-services01.etam-sb.kbrw.fr");
        assert_eq!(f.content, b"00:00:02.032 [info]  in GET /api/ping");
        // Les espaces de tête d'une stack trace sont conservés.
        let f = ElixirSyslog.frame(b"h.kbrw.fr      (app 0.1.0) lib/x.ex:211: Mod.fun/3");
        assert_eq!(f.content, b"    (app 0.1.0) lib/x.ex:211: Mod.fun/3");
        // Contenu vide : séparateur.
        let f = ElixirSyslog.frame(b"etam-admin01.etam-sb.kbrw.fr  ");
        assert_eq!(f.content, b"");
        // Pas de préfixe host plausible : toute la ligne est du contenu.
        let f = ElixirSyslog.frame(b"jean.dupont@example.com  a ecrit");
        assert_eq!(f.source, b"");
        let f = ElixirSyslog.frame(b"203.0.113.10  bonjour");
        assert_eq!(f.source, b"");
        // Séparateur sans ses espaces finaux.
        let f = ElixirSyslog.frame(b"etam-admin01.etam-sb.kbrw.fr");
        assert_eq!((f.source, f.content), (&b"etam-admin01.etam-sb.kbrw.fr"[..], &b""[..]));
    }

    #[test]
    fn classifies() {
        let c = |s: &[u8]| ElixirSyslog.classify(s);
        assert_eq!(c(b"09:39:05.203 [info]  in GET /x"), LineClass::Start { level: Some(Level::Info) });
        assert_eq!(c(b"15:25:21.157 [error] [Iam.Oauth] x"), LineClass::Start { level: Some(Level::Error) });
        assert_eq!(c(b"06:49:31.793 [warning] x"), LineClass::Start { level: Some(Level::Warning) });
        assert_eq!(c(b""), LineClass::Separator);
        assert_eq!(c(b"\tqs: %{}"), LineClass::Continuation);
        assert_eq!(c(b"** (ArgumentError) argument error"), LineClass::Continuation);
        assert_eq!(c(b"===== ALIVE Mon Nov  9 00:12:26 UTC 2026"), LineClass::Standalone(EntryKind::Alive));
        assert_eq!(c(b"====="), LineClass::Standalone(EntryKind::Alive));
        assert_eq!(c(b"===== LOGGING STARTED Mon Nov  9"), LineClass::Standalone(EntryKind::LoggingStarted));
        assert_eq!(c(b"storeofferevent.ETAM_0063.hourly:1|c"), LineClass::Standalone(EntryKind::Statsd));
        assert_eq!(
            c(b"ignore event beammetrics.gateway_in%402001%3A41d0.process/count:631|g|"),
            LineClass::Standalone(EntryKind::Other)
        );
        assert_eq!(
            c(b"[2026-11-09 00:51:59.786109Z UTC] An access_token was obtained"),
            LineClass::Standalone(EntryKind::IoTimestamped)
        );
        assert_eq!(c(b"message repeated 2 times: [ ]"), LineClass::Standalone(EntryKind::Repeated));
        assert_eq!(c(b"200 -> {\"delivery_modes\":[]}"), LineClass::Continuation);
    }

    #[test]
    fn message_start_skips_padding() {
        let h = b"09:39:05.203 [info]  in GET /x";
        assert_eq!(&h[ElixirSyslog.message_start(h)..], b"in GET /x");
        let h = b"06:49:31.793 [info] GET //api/user/M0000001";
        assert_eq!(&h[ElixirSyslog.message_start(h)..], b"GET //api/user/M0000001");
    }
}

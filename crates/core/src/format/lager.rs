//! `console.log` : lager (Riak) via syslog.
//!
//! Chaque ligne physique est `<host>␠␠<contenu>`. Une entrée commence par
//! `YYYY-MM-DD HH:MM:SS.mmm [level] <pid>@module:fonction:ligne message` ; les autres
//! lignes de la même source sont ses continuations, jusqu'à un séparateur (ligne vide
//! ou faite de codes ANSI) ou un nouveau début.

use super::{elixir, frame_syslog, Format, FormatKind, Framed, LineClass};
use crate::entry::Level;

pub struct LagerSyslog;

/// Longueur de `YYYY-MM-DD ` devant l'heure.
const DATE_LEN: usize = 11;

/// `YYYY-MM-DD HH:MM:SS.mmm [level]` en tête de contenu → (niveau, position après le `]`).
pub fn parse_start(c: &[u8]) -> Option<(Level, usize)> {
    if c.len() < DATE_LEN {
        return None;
    }
    let d = |i: usize| c[i].is_ascii_digit();
    if !(d(0) && d(1) && d(2) && d(3) && c[4] == b'-' && d(5) && d(6) && c[7] == b'-' && d(8) && d(9) && c[10] == b' ') {
        return None;
    }
    elixir::parse_start(&c[DATE_LEN..]).map(|(level, end)| (level, DATE_LEN + end))
}

impl Format for LagerSyslog {
    fn kind(&self) -> FormatKind {
        FormatKind::LagerSyslog
    }

    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a> {
        frame_syslog(line)
    }

    fn classify(&self, c: &[u8]) -> LineClass {
        if c.iter().all(|b| b.is_ascii_whitespace()) {
            return LineClass::Separator;
        }
        match parse_start(c) {
            Some((level, _)) => LineClass::Start { level: Some(level) },
            None => LineClass::Continuation,
        }
    }

    /// Après le niveau : le message commence au `<pid>`.
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
    use crate::assemble::{AssembleOptions, Assembler};
    use crate::entry::{Entry, EntryKind};
    use std::sync::Arc;

    #[test]
    fn classifies() {
        let c = |s: &[u8]| LagerSyslog.classify(s);
        assert_eq!(c(b"2026-11-09 00:01:05.050 [info] <0.24584.4878> Merged {[],[]} in 0.11353 seconds."), LineClass::Start { level: Some(Level::Info) });
        assert_eq!(c(b"2026-11-09 14:25:54.020 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object"), LineClass::Start { level: Some(Level::Warning) });
        for level in ["debug", "notice", "error", "critical", "alert", "emergency"] {
            assert!(matches!(c(format!("2026-11-09 14:25:54.020 [{level}] x").as_bytes()), LineClass::Start { level: Some(_) }), "{level}");
        }
        assert_eq!(c(b""), LineClass::Separator);
        assert_eq!(c(b"   "), LineClass::Separator);
        // Heure seule (Elixir), date sans heure, niveau inconnu, texte libre : continuations.
        assert_eq!(c(b"14:25:54.020 [info] x"), LineClass::Continuation);
        assert_eq!(c(b"2026-11-09 [info] x"), LineClass::Continuation);
        assert_eq!(c(b"2026-11-09 14:25:54.020 [chatty] x"), LineClass::Continuation);
        assert_eq!(c(b"2026-11-09T14:25:54.020 [info] x"), LineClass::Continuation);
        assert_eq!(c(b"    {riak_kv_vnode,do_get_object,3,[{file,\"src/riak_kv_vnode.erl\"},{line,1837}]}"), LineClass::Continuation);
        assert_eq!(c(b"2026-11-09"), LineClass::Continuation);
    }

    #[test]
    fn message_starts_at_the_pid() {
        let h = b"2026-11-09 14:25:54.020 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object";
        assert_eq!(&h[LagerSyslog.message_start(h)..], &b"<0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object"[..]);
        assert_eq!(LagerSyslog.message_start(b"    continuation"), 0);
    }

    fn assemble(input: &[u8], opts: AssembleOptions) -> Vec<Entry> {
        let mut a = Assembler::new(Arc::new(LagerSyslog), opts);
        let mut out = Vec::new();
        for line in input.split(|b| *b == b'\n') {
            a.push_line(line, &mut out);
        }
        a.finish(&mut out);
        out
    }

    #[test]
    fn multiline_entries_interleaved_between_hosts() {
        let input = b"riakn04.etam-sb.kbrw.fr  2026-11-09 14:25:54.020 [error] <0.1166.0>@riak_kv_vnode:handle_command:912 CRASH REPORT Process <0.1166.0> with 0 neighbours crashed\r\n\
riakn07.etam-sb.kbrw.fr  2026-11-09 14:25:54.021 [info] <0.24584.4878> Merged {[\"/var/lib/riak/bitcask/1/2.bitcask.data\"],[]} in 0.11353 seconds.\r\n\
riakn04.etam-sb.kbrw.fr      {badmatch,{error,timeout}}\r\n\
riakn07.etam-sb.kbrw.fr  2026-11-09 14:25:54.022 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object <<\"b\">>/<<\"k\">> (5652713 bytes)\r\n\
riakn04.etam-sb.kbrw.fr      [{riak_kv_vnode,do_get_object,3,[{file,\"src/riak_kv_vnode.erl\"},{line,1837}]}]\r\n\
riakn04.etam-sb.kbrw.fr  \x1b[0m\r\n\
riakn04.etam-sb.kbrw.fr  after the separator\r\n";
        let e = assemble(input, AssembleOptions::default());
        let texts: Vec<String> = e.iter().map(|x| String::from_utf8_lossy(&x.text).into_owned()).collect();
        assert_eq!(
            texts,
            vec![
                "2026-11-09 14:25:54.020 [error] <0.1166.0>@riak_kv_vnode:handle_command:912 CRASH REPORT Process <0.1166.0> with 0 neighbours crashed\n    {badmatch,{error,timeout}}\n    [{riak_kv_vnode,do_get_object,3,[{file,\"src/riak_kv_vnode.erl\"},{line,1837}]}]",
                "2026-11-09 14:25:54.021 [info] <0.24584.4878> Merged {[\"/var/lib/riak/bitcask/1/2.bitcask.data\"],[]} in 0.11353 seconds.",
                "2026-11-09 14:25:54.022 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object <<\"b\">>/<<\"k\">> (5652713 bytes)",
                "after the separator",
            ]
        );
        assert_eq!(e.iter().map(|x| x.line_no).collect::<Vec<_>>(), vec![1, 2, 4, 7]);
        assert_eq!(e.iter().map(|x| x.kind).collect::<Vec<_>>(), vec![EntryKind::Logger, EntryKind::Logger, EntryKind::Logger, EntryKind::Orphan]);
        assert_eq!(e.iter().map(|x| x.level).collect::<Vec<_>>(), vec![Some(Level::Error), Some(Level::Info), Some(Level::Warning), None]);
        assert_eq!(e.iter().map(|x| &*x.source).collect::<Vec<_>>(), vec!["riakn04.etam-sb.kbrw.fr", "riakn07.etam-sb.kbrw.fr", "riakn07.etam-sb.kbrw.fr", "riakn04.etam-sb.kbrw.fr"]);
        assert_eq!(e[0].lines, 3);
    }

    #[test]
    fn long_entry_is_cut_on_a_line_boundary() {
        let mut input = b"r.kbrw.fr  2026-11-09 14:25:54.020 [error] <0.1.0> start".to_vec();
        for i in 0..7 {
            input.extend_from_slice(format!("\nr.kbrw.fr      frame {i}").as_bytes());
        }
        let e = assemble(&input, AssembleOptions { max_entry_lines: 4, ..Default::default() });
        assert_eq!(e.iter().map(|x| x.lines).collect::<Vec<_>>(), vec![4, 4]);
        assert_eq!(e[1].kind, EntryKind::Orphan);
    }
}

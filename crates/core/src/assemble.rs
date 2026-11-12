//! Assemblage des lignes en entrées : une entrée ouverte par source, restitution dans
//! l'ordre de la première ligne grâce à un tampon de réordonnancement borné.

use crate::ansi;
use crate::entry::{Entry, EntryKind};
use crate::format::{Format, LineClass};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct AssembleOptions {
    pub strip_ansi: bool,
    pub max_entry_lines: u32,
    pub max_entry_bytes: usize,
    /// Nombre maximal d'entrées retenues derrière une entrée encore ouverte.
    pub reorder_window: usize,
    /// Octets maximaux retenus dans le tampon de réordonnancement.
    pub reorder_bytes: usize,
}

impl Default for AssembleOptions {
    fn default() -> Self {
        AssembleOptions {
            strip_ansi: true,
            max_entry_lines: 2000,
            max_entry_bytes: 1 << 20,
            reorder_window: 4096,
            reorder_bytes: 8 << 20,
        }
    }
}

struct Slot {
    entry: Entry,
    closed: bool,
}

pub struct Assembler {
    fmt: Arc<dyn Format>,
    opts: AssembleOptions,
    sources: HashMap<Vec<u8>, Arc<str>>,
    /// Source → clé (numéro de première ligne) de son entrée ouverte.
    open: HashMap<Arc<str>, u64>,
    pending: BTreeMap<u64, Slot>,
    pending_bytes: usize,
    scratch: Vec<u8>,
    line_no: u64,
}

impl Assembler {
    pub fn new(fmt: Arc<dyn Format>, opts: AssembleOptions) -> Self {
        Assembler {
            fmt,
            opts,
            sources: HashMap::new(),
            open: HashMap::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            scratch: Vec::new(),
            line_no: 0,
        }
    }

    pub fn lines_seen(&self) -> u64 {
        self.line_no
    }

    fn intern(&mut self, source: &[u8]) -> Arc<str> {
        if let Some(s) = self.sources.get(source) {
            return s.clone();
        }
        // `frame` garantit un host ASCII ; le repli « lossy » ne sert jamais en pratique.
        let s: Arc<str> = Arc::from(String::from_utf8_lossy(source).as_ref());
        self.sources.insert(source.to_vec(), s.clone());
        s
    }

    fn close(&mut self, source: &Arc<str>) {
        if let Some(key) = self.open.remove(source) {
            if let Some(slot) = self.pending.get_mut(&key) {
                slot.closed = true;
            }
        }
    }

    fn open_entry(&mut self, source: Arc<str>, kind: EntryKind, level: Option<crate::entry::Level>, content: &[u8], closed: bool) {
        let entry = Entry { source: source.clone(), line_no: self.line_no, kind, level, text: content.to_vec(), lines: 1 };
        self.pending_bytes += content.len();
        self.pending.insert(self.line_no, Slot { entry, closed });
        if !closed {
            self.open.insert(source, self.line_no);
        }
    }

    /// Pousse une ligne physique (sans `\n`). Les entrées prêtes sont ajoutées à `out`, dans l'ordre.
    pub fn push_line(&mut self, line: &[u8], out: &mut Vec<Entry>) {
        self.line_no += 1;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let framed = self.fmt.frame(line);
        let source = self.intern(framed.source);

        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.clear();
        let content: &[u8] = if self.opts.strip_ansi && ansi::has_esc(framed.content) {
            ansi::strip_ansi(framed.content, &mut scratch);
            &scratch
        } else {
            framed.content
        };

        match self.fmt.classify(content) {
            LineClass::Separator => self.close(&source),
            LineClass::Start { level } => {
                self.close(&source);
                self.open_entry(source, EntryKind::Logger, level, content, false);
            }
            LineClass::Standalone(kind) => {
                self.close(&source);
                self.open_entry(source, kind, None, content, true);
            }
            LineClass::Continuation => {
                let mut appended = false;
                if let Some(&key) = self.open.get(&source) {
                    if let Some(slot) = self.pending.get_mut(&key) {
                        let e = &mut slot.entry;
                        if e.lines < self.opts.max_entry_lines && e.text.len() + content.len() < self.opts.max_entry_bytes {
                            e.text.push(b'\n');
                            e.text.extend_from_slice(content);
                            e.lines += 1;
                            self.pending_bytes += content.len() + 1;
                            appended = true;
                        }
                    }
                }
                if !appended {
                    // Entrée trop longue (coupée ici) ou continuation sans entrée ouverte.
                    self.close(&source);
                    self.open_entry(source, EntryKind::Orphan, None, content, false);
                }
            }
        }
        self.scratch = scratch;
        self.drain(out, false);
    }

    /// Fin du flux : ferme et restitue tout.
    pub fn finish(&mut self, out: &mut Vec<Entry>) {
        self.drain(out, true);
    }

    fn drain(&mut self, out: &mut Vec<Entry>, all: bool) {
        while let Some((&key, slot)) = self.pending.iter().next() {
            let over = self.pending.len() > self.opts.reorder_window || self.pending_bytes > self.opts.reorder_bytes;
            if !(slot.closed || all || over) {
                break;
            }
            let slot = self.pending.remove(&key).expect("clé présente");
            if !slot.closed {
                self.open.remove(&slot.entry.source);
            }
            self.pending_bytes = self.pending_bytes.saturating_sub(slot.entry.text.len());
            out.push(slot.entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{make_format, FormatKind};

    fn assemble(input: &[u8], opts: AssembleOptions) -> Vec<Entry> {
        let mut a = Assembler::new(make_format(FormatKind::ElixirSyslog).unwrap(), opts);
        let mut out = Vec::new();
        for line in input.split(|b| *b == b'\n') {
            a.push_line(line, &mut out);
        }
        a.finish(&mut out);
        out
    }

    fn texts(entries: &[Entry]) -> Vec<String> {
        entries.iter().map(|e| String::from_utf8_lossy(&e.text).into_owned()).collect()
    }

    #[test]
    fn interleaved_sources_are_regrouped_in_first_line_order() {
        let input = b"s1.kbrw.fr  00:00:02.032 [info]  A\n\
s3.kbrw.fr  00:00:02.033 [error] B\n\
s1.kbrw.fr  \tcookie : x=1\n\
s3.kbrw.fr  ** (ArgumentError) argument error\n\
s1.kbrw.fr  \t#Reference<0.1.2.3>\n\
s3.kbrw.fr      :erlang.element(2, nil)";
        let e = assemble(input, AssembleOptions::default());
        assert_eq!(
            texts(&e),
            vec![
                "00:00:02.032 [info]  A\n\tcookie : x=1\n\t#Reference<0.1.2.3>",
                "00:00:02.033 [error] B\n** (ArgumentError) argument error\n    :erlang.element(2, nil)",
            ]
        );
        assert_eq!(e[0].line_no, 1);
        assert_eq!(e[1].line_no, 2);
        assert_eq!(&*e[0].source, "s1.kbrw.fr");
    }

    #[test]
    fn ansi_only_line_is_a_separator_and_crlf_is_dropped() {
        let input = b"j.kbrw.fr  10:00:00.000 [debug] one\r\n\
j.kbrw.fr  \x1b[0m\x1b[36m\r\n\
j.kbrw.fr  trailing after separator\r\n\
j.kbrw.fr  10:00:01.000 [debug] two\r";
        let e = assemble(input, AssembleOptions::default());
        assert_eq!(
            texts(&e),
            vec!["10:00:00.000 [debug] one", "trailing after separator", "10:00:01.000 [debug] two"]
        );
        assert_eq!(e[1].kind, EntryKind::Orphan);
    }

    #[test]
    fn start_opens_without_separator_and_standalone_closes() {
        let input = b"h.kbrw.fr  10:00:00.000 [info]  one\n\
h.kbrw.fr  10:00:00.001 [info]  two\n\
h.kbrw.fr  ===== ALIVE Mon Nov  9 00:12:26 UTC 2026\n\
h.kbrw.fr  after alive";
        let e = assemble(input, AssembleOptions::default());
        assert_eq!(e.len(), 4);
        assert_eq!(e[2].kind, EntryKind::Alive);
        assert_eq!(e[3].kind, EntryKind::Orphan);
    }

    #[test]
    fn long_entry_is_cut_on_a_line_boundary() {
        let mut input = b"h.kbrw.fr  10:00:00.000 [info]  start".to_vec();
        for i in 0..10 {
            input.extend_from_slice(format!("\nh.kbrw.fr  cont {i}").as_bytes());
        }
        let e = assemble(&input, AssembleOptions { max_entry_lines: 4, ..Default::default() });
        assert_eq!(e.iter().map(|x| x.lines).collect::<Vec<_>>(), vec![4, 4, 3]);
        assert_eq!(e[1].kind, EntryKind::Orphan);
    }

    #[test]
    fn silent_source_does_not_hold_the_stream_forever() {
        let mut input = b"quiet.kbrw.fr  10:00:00.000 [info]  never closed".to_vec();
        for i in 0..20 {
            input.extend_from_slice(format!("\nbusy.kbrw.fr  10:00:01.{:03} [info]  n{i}\nbusy.kbrw.fr  ", i).as_bytes());
        }
        let mut a = Assembler::new(
            make_format(FormatKind::ElixirSyslog).unwrap(),
            AssembleOptions { reorder_window: 5, ..Default::default() },
        );
        let mut out = Vec::new();
        for line in input.split(|b| *b == b'\n') {
            a.push_line(line, &mut out);
        }
        // Avant la fin du flux, l'entrée muette a été fermée d'office et la suite est sortie.
        assert!(out.len() >= 14, "sorties avant finish : {}", out.len());
        assert_eq!(out[0].line_no, 1);
        a.finish(&mut out);
        assert_eq!(out.len(), 21);
        assert!(out.windows(2).all(|w| w[0].line_no < w[1].line_no));
    }
}

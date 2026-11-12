//! Traitement d'un flux complet, en mémoire bornée.
//!
//! Un thread lit, décompresse, découpe en lignes et assemble les entrées en lots
//! d'environ 4 Mo ; les lots sont traités en parallèle (`rayon`) puis écrits dans l'ordre.

use crate::assemble::Assembler;
use crate::engine::{Engine, Outcome, Scratch, Trace};
use crate::entry::Entry;
use crate::error::{CoreError, Result};
use crate::output::{EntrySink, WriteSink};
use crate::rules::Dedup;
use crate::safety::Sanitized;
use crate::stats::Stats;
use memchr::memchr;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Layout {
    /// Host une seule fois, sur la première ligne ; continuations indentées de deux espaces.
    #[default]
    Compact,
    /// Préfixe `host␠␠` sur chaque ligne, comme dans le fichier d'origine.
    Faithful,
}

#[derive(Clone, Copy, Debug)]
pub struct RunOptions {
    pub layout: Layout,
    /// Taille visée d'un lot d'entrées, en octets de texte.
    pub batch_bytes: usize,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { layout: Layout::Compact, batch_bytes: 4 << 20 }
    }
}

/// Avancement, transmis après chaque groupe de lots.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Progress {
    pub entries_in: u64,
    pub entries_out: u64,
    pub dropped: u64,
    pub modified: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

const READ_CHUNK: usize = 1 << 20;
/// Une ligne physique plus longue est coupée (aucun log réel n'approche cette taille).
const MAX_LINE: usize = 16 << 20;

/// Compte les octets lus du fichier, avant décompression.
struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Un fichier de log ouvert, avec de quoi suivre l'avancement de sa lecture.
pub struct Input {
    pub reader: Box<dyn Read + Send>,
    /// Octets lus sur le disque jusqu'ici (compressés si le fichier l'est).
    pub read: Arc<AtomicU64>,
    /// Taille du fichier sur le disque.
    pub size: u64,
}

/// Ouvre un fichier de log, compressé (gzip, éventuellement en plusieurs membres) ou non,
/// en comptant les octets lus : `read / size` donne l'avancement, y compris pour un gzip
/// dont on ne connaît pas la taille décompressée.
pub fn open_input_counted(path: &Path) -> Result<Input> {
    let file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let read = Arc::new(AtomicU64::new(0));
    let mut reader = BufReader::with_capacity(READ_CHUNK, CountingReader { inner: file, count: read.clone() });
    let gz = reader.fill_buf()?.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read + Send> = if gz { Box::new(flate2::bufread::MultiGzDecoder::new(reader)) } else { Box::new(reader) };
    Ok(Input { reader, read, size })
}

/// Ouvre un fichier de log, compressé (gzip, éventuellement en plusieurs membres) ou non.
pub fn open_input(path: &Path) -> Result<Box<dyn Read + Send>> {
    Ok(open_input_counted(path)?.reader)
}

/// Écrit une entrée anonymisée selon la disposition choisie.
pub fn write_entry(layout: Layout, source: &str, text: &[u8], out: &mut Vec<u8>) {
    let mut first = true;
    for line in text.split(|b| *b == b'\n') {
        match layout {
            Layout::Compact if !first => out.extend_from_slice(b"  "),
            Layout::Compact | Layout::Faithful if !source.is_empty() && (first || layout == Layout::Faithful) => {
                out.extend_from_slice(source.as_bytes());
                out.extend_from_slice(b"  ");
            }
            _ => {}
        }
        out.extend_from_slice(line);
        out.push(b'\n');
        first = false;
    }
}

/// Sortie anonymisée d'un lot.
pub struct BatchOut {
    pub bytes: Sanitized,
    /// Fin de chaque entrée gardée, dans `bytes`.
    pub ends: Vec<u32>,
    /// Si le template déduplique : (indice de l'entrée dans le lot, empreinte de comparaison),
    /// dans le même ordre que `ends`.
    pub hashes: Vec<(u32, u64)>,
}

fn starts_with_time(t: &[u8]) -> bool {
    t.len() >= 12 && t[2] == b':' && t[5] == b':' && t[8] == b'.' && [0, 1, 3, 4, 6, 7, 9, 10, 11].iter().all(|&i| t[i].is_ascii_digit())
}

/// Longueur de `YYYY-MM-DD ` devant l'heure d'une entrée lager.
const DATE_LEN: usize = 11;

/// Plage de l'heure `HH:MM:SS.mmm` en tête d'entrée : seule (Elixir) ou après la date (lager).
fn time_range(t: &[u8]) -> Option<(usize, usize)> {
    if starts_with_time(t) {
        return Some((0, 12));
    }
    let dated = t.len() > DATE_LEN && t[4] == b'-' && t[7] == b'-' && t[10] == b' ' && [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&i| t[i].is_ascii_digit());
    (dated && starts_with_time(&t[DATE_LEN..])).then_some((DATE_LEN, DATE_LEN + 12))
}

/// Longueur d'un pid Erlang nu `<0.1166.0>` en tête de `t` (notation de lager).
fn bare_pid_len(t: &[u8]) -> Option<usize> {
    let end = memchr(b'>', &t[..t.len().min(40)])?;
    let inner = &t[1..end];
    let ok = inner.iter().filter(|b| **b == b'.').count() == 2 && inner.split(|b| *b == b'.').all(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit));
    ok.then_some(end + 1)
}

/// Empreinte d'une entrée pour la déduplication : l'horodatage, les pids (`#PID<…>`,
/// `<0.1166.0>`) et les `#Reference<…>` n'y entrent pas si le template demande de les ignorer.
fn dedup_hash(text: &[u8], d: &Dedup) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    let mut feed = |b: u8| h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    let mut i = if d.ignore_timestamp { time_range(text).map_or(0, |(_, end)| end) } else { 0 };
    while i < text.len() {
        if d.ignore_pid && text[i] == b'<' {
            if let Some(len) = bare_pid_len(&text[i..]) {
                feed(b'<');
                i += len;
                continue;
            }
        }
        if text[i] == b'#' {
            let rest = &text[i..];
            let opaque = (d.ignore_pid && rest.starts_with(b"#PID<")) || (d.ignore_reference && rest.starts_with(b"#Reference<"));
            if let Some(end) = memchr(b'>', rest).filter(|_| opaque) {
                feed(b'#');
                i += end + 1;
                continue;
            }
        }
        feed(text[i]);
        i += 1;
    }
    h
}

impl Engine {
    /// Traite un lot d'entrées et rend la sortie anonymisée correspondante.
    pub fn process_batch(&self, entries: &[Entry], layout: Layout, sc: &mut Scratch) -> (BatchOut, Stats) {
        let mut stats = self.new_stats();
        let dedup = self.template().dedup.as_ref();
        let mut out = Vec::with_capacity(entries.iter().map(|e| e.text.len() + 48).sum());
        let mut ends = Vec::with_capacity(entries.len());
        let mut hashes = Vec::new();
        let mut text = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            text.clear();
            if let Outcome::Kept { .. } = self.process(entry, sc, &mut text, &mut stats, None) {
                write_entry(layout, &entry.source, &text, &mut out);
                ends.push(out.len() as u32);
                if let Some(d) = dedup {
                    hashes.push((i as u32, dedup_hash(&text, d)));
                }
            }
        }
        (BatchOut { bytes: Sanitized::seal(out), ends, hashes }, stats)
    }
}

/// État de la déduplication pour une source : la dernière entrée écrite et ses répétitions.
struct Repeat {
    hash: u64,
    count: u64,
    last_time: [u8; 12],
}

fn repeat_marker(source: &str, r: &Repeat) -> Vec<u8> {
    let mut line = Vec::with_capacity(source.len() + 80);
    if !source.is_empty() {
        line.extend_from_slice(source.as_bytes());
        line.extend_from_slice(b"  ");
    }
    line.extend_from_slice(format!("↳ entrée précédente répétée {} fois", r.count).as_bytes());
    if r.last_time[0] != 0 {
        line.extend_from_slice(", la dernière à ".as_bytes());
        line.extend_from_slice(&r.last_time);
    }
    line.push(b'\n');
    line
}

pub(crate) enum Item {
    Batch(Vec<Entry>),
    InputError(String),
}

pub(crate) fn produce<R: Read>(mut input: R, engine: &Engine, tx: crossbeam_channel::Sender<Item>, cancel: &AtomicBool, batch_bytes: usize) {
    let mut asm = Assembler::new(engine.format(), engine.template().assemble);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut carry: Vec<u8> = Vec::new();
    let mut ready: Vec<Entry> = Vec::new();
    let mut batch: Vec<Entry> = Vec::new();
    let mut size = 0usize;

    let flush = |ready: &mut Vec<Entry>, batch: &mut Vec<Entry>, size: &mut usize, force: bool| -> bool {
        for e in ready.drain(..) {
            *size += e.text.len() + 64;
            batch.push(e);
            if *size >= batch_bytes {
                *size = 0;
                if tx.send(Item::Batch(std::mem::take(batch))).is_err() {
                    return false;
                }
            }
        }
        if force && !batch.is_empty() {
            *size = 0;
            return tx.send(Item::Batch(std::mem::take(batch))).is_ok();
        }
        true
    };

    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Fichier tronqué ou corrompu : on traite ce qui a pu être lu et on le signale.
                let _ = tx.send(Item::InputError(e.to_string()));
                break;
            }
        };
        let mut chunk = &buf[..n];
        while let Some(nl) = memchr(b'\n', chunk) {
            if carry.is_empty() {
                asm.push_line(&chunk[..nl], &mut ready);
            } else {
                carry.extend_from_slice(&chunk[..nl]);
                asm.push_line(&carry, &mut ready);
                carry.clear();
            }
            chunk = &chunk[nl + 1..];
        }
        carry.extend_from_slice(chunk);
        if carry.len() > MAX_LINE {
            asm.push_line(&carry, &mut ready);
            carry.clear();
        }
        if !flush(&mut ready, &mut batch, &mut size, false) {
            return;
        }
    }
    if !carry.is_empty() {
        asm.push_line(&carry, &mut ready);
    }
    asm.finish(&mut ready);
    flush(&mut ready, &mut batch, &mut size, true);
}

/// Anonymise `input` vers `out`. `progress` est appelé régulièrement ; `cancel` interrompt
/// le traitement (erreur [`CoreError::Cancelled`]).
pub fn run<R: Read + Send, W: Write>(
    input: R,
    engine: &Engine,
    out: &mut W,
    opts: &RunOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Stats> {
    run_to_sink(input, engine, &mut WriteSink(out), opts, cancel, progress)
}

/// Comme [`run`], vers une destination qui connaît les frontières d'entrées (découpage en parties).
pub fn run_to_sink<R: Read + Send>(
    input: R,
    engine: &Engine,
    sink: &mut dyn EntrySink,
    opts: &RunOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Stats> {
    let group = rayon::current_num_threads().max(1) * 2;
    let (tx, rx) = crossbeam_channel::bounded::<Item>(group);
    let mut total = engine.new_stats();
    let dedup = engine.template().dedup.is_some();
    let mut repeats: HashMap<Arc<str>, Repeat> = HashMap::new();
    std::thread::scope(|scope| -> Result<()> {
        scope.spawn(move || produce(input, engine, tx, cancel, opts.batch_bytes));
        // Le récepteur appartient à cette fermeture : s'il est lâché sur une sortie anticipée
        // (annulation, erreur d'écriture), le producteur bloqué sur un canal plein se termine.
        let rx = rx;
        loop {
            let mut batches: Vec<Vec<Entry>> = Vec::with_capacity(group);
            let mut next = rx.recv().ok();
            if next.is_none() {
                break;
            }
            while let Some(item) = next.take() {
                match item {
                    Item::Batch(b) => batches.push(b),
                    Item::InputError(msg) => total.input_error = Some(msg),
                }
                if batches.len() < group {
                    next = rx.try_recv().ok();
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }
            let results: Vec<(BatchOut, Stats)> =
                batches.par_iter().map_init(Scratch::default, |sc, b| engine.process_batch(b, opts.layout, sc)).collect();
            for (batch, (out, stats)) in batches.iter().zip(results) {
                total.merge(stats);
                let bytes = out.bytes.as_bytes();
                if !dedup {
                    sink.write(bytes, &out.ends)?;
                    continue;
                }
                // Une entrée identique à la précédente de la même source n'est pas réécrite :
                // un compteur la remplace, posé juste avant l'entrée différente qui suit.
                let mut start = 0usize;
                for (&end, &(idx, hash)) in out.ends.iter().zip(&out.hashes) {
                    let entry = &batch[idx as usize];
                    let piece = &bytes[start..end as usize];
                    start = end as usize;
                    let mut time = [0u8; 12];
                    if let Some((s, e)) = time_range(&entry.text) {
                        time.copy_from_slice(&entry.text[s..e]);
                    }
                    match repeats.get_mut(&entry.source) {
                        Some(r) if r.hash == hash => {
                            r.count += 1;
                            r.last_time = time;
                            total.deduplicated += 1;
                            total.entries_out -= 1;
                            total.bytes_out = total.bytes_out.saturating_sub(piece.len() as u64);
                        }
                        previous => {
                            if let Some(r) = previous.filter(|r| r.count > 0) {
                                let marker = repeat_marker(&entry.source, r);
                                sink.write(&marker, &[marker.len() as u32])?;
                            }
                            sink.write(piece, &[piece.len() as u32])?;
                            repeats.insert(entry.source.clone(), Repeat { hash, count: 0, last_time: time });
                        }
                    }
                }
            }
            progress(&Progress {
                entries_in: total.entries_in,
                entries_out: total.entries_out,
                dropped: total.dropped,
                modified: total.modified,
                bytes_in: total.bytes_in,
                bytes_out: total.bytes_out,
            });
        }
        Ok(())
    })?;
    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled);
    }
    // Répétitions encore en attente à la fin du flux.
    let mut pending: Vec<_> = repeats.iter().filter(|(_, r)| r.count > 0).collect();
    pending.sort_by(|a, b| a.0.cmp(b.0));
    for (source, r) in pending {
        let marker = repeat_marker(source, r);
        sink.write(&marker, &[marker.len() as u32])?;
    }
    sink.finish()?;
    Ok(total)
}

/// Un morceau de texte du bac à sable, éventuellement attribué à une règle.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub rule: Option<String>,
    pub safety: bool,
}

/// Une entrée vue côte à côte : texte brut et texte anonymisé, découpés aux remplacements.
#[derive(Clone, Debug, Serialize)]
pub struct SandboxEntry {
    pub source: String,
    pub line_no: u64,
    pub kind: String,
    /// Filtre ou règle qui a supprimé l'entrée.
    pub dropped_by: Option<String>,
    pub raw: Vec<Segment>,
    pub out: Vec<Segment>,
}

fn segments(text: &[u8], ranges: &[((usize, usize), &str, bool)]) -> Vec<Segment> {
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let mut segs = Vec::new();
    let mut pos = 0;
    for ((s, e), rule, safety) in ranges {
        let (s, e) = ((*s).clamp(pos, text.len()), (*e).clamp(pos, text.len()));
        if s > pos {
            segs.push(Segment { text: lossy(&text[pos..s]), rule: None, safety: false });
        }
        segs.push(Segment { text: lossy(&text[s..e]), rule: Some(rule.to_string()), safety: *safety });
        pos = e;
    }
    if pos < text.len() {
        segs.push(Segment { text: lossy(&text[pos..]), rule: None, safety: false });
    }
    segs
}

/// Assemble les lignes de `input` en entrées, avec le format du template.
pub fn assemble_all(engine: &Engine, input: &[u8]) -> Vec<Entry> {
    let mut asm = Assembler::new(engine.format(), engine.template().assemble);
    let mut entries = Vec::new();
    let body = input.strip_suffix(b"\n").unwrap_or(input);
    if !body.is_empty() {
        for line in body.split(|b| *b == b'\n') {
            asm.push_line(line, &mut entries);
        }
    }
    asm.finish(&mut entries);
    entries
}

/// Bac à sable : traite des lignes collées et rend, pour chaque entrée, le brut et
/// l'anonymisé découpés aux remplacements, avec la règle responsable.
pub fn sandbox(engine: &Engine, input: &[u8], max_entries: usize) -> (Vec<SandboxEntry>, Stats) {
    let mut stats = engine.new_stats();
    let mut sc = Scratch::default();
    let mut result = Vec::new();
    let mut out = Vec::new();
    for entry in assemble_all(engine, input).into_iter().take(max_entries) {
        out.clear();
        let mut trace = Trace::default();
        let outcome = engine.process(&entry, &mut sc, &mut out, &mut stats, Some(&mut trace));
        let raw: Vec<_> = trace.edits.iter().map(|e| (e.src, e.rule.as_str(), e.safety)).collect();
        let mut outs: Vec<_> = trace.edits.iter().map(|e| (e.out, e.rule.as_str(), e.safety)).collect();
        outs.sort_by_key(|(r, _, _)| r.0);
        result.push(SandboxEntry {
            source: entry.source.to_string(),
            line_no: entry.line_no,
            kind: entry.kind.as_str().to_string(),
            dropped_by: trace.dropped_by.clone(),
            raw: segments(&entry.text, &raw),
            out: if outcome == Outcome::Dropped { Vec::new() } else { segments(&out, &outs) },
        });
    }
    (result, stats)
}

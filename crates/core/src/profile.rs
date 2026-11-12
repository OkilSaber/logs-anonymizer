//! Profilage d'un fichier de logs : de quoi il est fait, et ce qui y reste en clair.
//!
//! - **Formes** : chaque entrée est ramenée à une forme (chiffres, chaînes et jetons
//!   masqués) ; on compte combien de fois chaque forme revient et ce qu'elle pèse.
//!   Chaque forme vient avec la regex d'un filtre qui la retirerait.
//! - **Inventaire des clés** : chaque chemin de clé vu par les extracteurs, sa fréquence,
//!   la part de ses valeurs remplacées et la forme masquée de celles qui ne le sont pas.
//!
//! Tout est calculé sur la sortie **anonymisée** : le profil ne contient jamais une valeur.

use crate::engine::{Engine, Outcome, Scratch};
use crate::entry::Entry;
use crate::error::{CoreError, Result};
use crate::extract::{self, Spans};
use crate::pipeline::{produce, Item};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

const SHAPE_MAX: usize = 110;
const DISTINCT_CAP: usize = 20_000;
const VALUE_SHAPES_CAP: usize = 40;

#[derive(Clone, Copy, Debug)]
pub struct ProfileOptions {
    /// Formes distinctes suivies ; au-delà, elles sont comptées ensemble.
    pub max_shapes: usize,
    pub max_keys: usize,
    /// Formes et clés rendues, les plus lourdes d'abord.
    pub top_shapes: usize,
    pub top_keys: usize,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        ProfileOptions { max_shapes: 60_000, max_keys: 30_000, top_shapes: 400, top_keys: 800 }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ShapeStat {
    /// Forme lisible : `Sent 0 in 0ms POST /api/x`.
    pub shape: String,
    /// Regex d'en-tête pour un filtre qui retirerait cette forme.
    pub pattern: String,
    pub count: u64,
    pub bytes: u64,
    pub level: String,
    pub kind: String,
    /// Entrées de cette forme qu'un filtre du template retire déjà. Une forme masque les
    /// chaînes et les nombres : elle peut n'être filtrée qu'en partie.
    pub filtered_count: u64,
    /// Filtre du template qui les retire.
    pub filtered_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct KeyStat {
    /// Chemin de clé : `properties.firstname`.
    pub path: String,
    pub count: u64,
    /// Valeurs remplacées par un jeton ou un masque.
    pub replaced: u64,
    /// Valeurs distinctes restées en clair (plafonné).
    pub distinct: u64,
    pub distinct_capped: bool,
    /// Formes masquées des valeurs en clair, les plus fréquentes d'abord : `Aa+`, `0+`.
    pub shapes: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Profile {
    pub entries: u64,
    pub bytes: u64,
    /// Entrées et octets que les filtres du template retirent.
    pub filtered_entries: u64,
    pub filtered_bytes: u64,
    pub shapes_total: u64,
    pub shapes: Vec<ShapeStat>,
    pub keys_total: u64,
    pub keys: Vec<KeyStat>,
    pub input_error: Option<String>,
}

/// `EMAIL_7f3a2c9d` → longueur du jeton, s'il commence à `i`.
fn token_at(t: &[u8], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    while j < t.len() && (t[j].is_ascii_uppercase() || t[j].is_ascii_digit()) && j - i < 16 {
        j += 1;
    }
    if j - i < 2 || !t[i].is_ascii_uppercase() || t.get(j) != Some(&b'_') {
        return None;
    }
    let label_end = j;
    j += 1;
    let hex_start = j;
    while j < t.len() && t[j].is_ascii_hexdigit() && !t[j].is_ascii_uppercase() {
        j += 1;
    }
    (j - hex_start >= 8 && !t.get(j).is_some_and(|b| b.is_ascii_alphanumeric())).then_some((label_end, j))
}

/// Jeton ou masque produit par le moteur : la valeur est déjà remplacée.
pub fn is_replaced(v: &[u8]) -> bool {
    let placeholder = v.len() > 2 && v[0] == b'[' && v[v.len() - 1] == b']' && v[1..v.len() - 1].iter().all(|b| b.is_ascii_uppercase() || *b == b'_');
    placeholder || token_at(v, 0).is_some_and(|(_, end)| end == v.len())
}

/// Forme masquée d'une valeur : lettres → `a`/`A`, chiffres → `0`, le reste → `*`,
/// suites réduites. `Jean` → `Aa+`, `75000` → `0+`.
pub fn mask_value(v: &[u8]) -> String {
    let mut out = String::new();
    let (mut last, mut run) = (' ', 0);
    for &b in v.iter().take(80) {
        let c = match b {
            b'a'..=b'z' => 'a',
            b'A'..=b'Z' => 'A',
            b'0'..=b'9' => '0',
            b' ' | b'_' | b'-' => b as char,
            _ => '*',
        };
        if c == last {
            run += 1;
            if run == 2 {
                out.push('+');
            }
        } else {
            out.push(c);
            last = c;
            run = 0;
        }
    }
    out.chars().take(28).collect()
}

fn push_literal(pattern: &mut String, bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            for ch in s.chars() {
                match ch {
                    '\t' => pattern.push_str("\\t"),
                    c if c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '/' || !c.is_ascii() => pattern.push(c),
                    c => {
                        pattern.push('\\');
                        pattern.push(c);
                    }
                }
            }
        }
        Err(_) => pattern.push('.'),
    }
}

/// Forme d'un message anonymisé et regex correspondante.
///
/// Les nombres deviennent `0`, les chaînes entre guillemets `"…"`, les jetons `‹EMAIL›`,
/// les suites hexadécimales `‹hex›`. La regex reconnaît le même préfixe du message.
pub fn shape_of(msg: &[u8]) -> (String, String) {
    let (mut shape, mut pattern) = (String::new(), String::new());
    let mut i = 0;
    let mut lit = 0;
    macro_rules! flush {
        ($to:expr) => {
            if lit < $to {
                shape.push_str(&String::from_utf8_lossy(&msg[lit..$to]));
                push_literal(&mut pattern, &msg[lit..$to]);
            }
        };
    }
    while i < msg.len() && shape.chars().count() < SHAPE_MAX {
        let b = msg[i];
        let boundary = i == 0 || !msg[i - 1].is_ascii_alphanumeric();
        if b == b'"' || b == b'\'' {
            // Chaîne fermée sur la même ligne ; sinon le guillemet reste un littéral.
            if let Some(len) = msg[i + 1..].iter().position(|c| *c == b || *c == b'\n').filter(|l| msg[i + 1 + l] == b) {
                flush!(i);
                let q = b as char;
                shape.push(q);
                shape.push('…');
                shape.push(q);
                pattern.push_str(if b == b'"' { "\"[^\"]*\"" } else { "'[^']*'" });
                i += len + 2;
                lit = i;
                continue;
            }
        } else if boundary && b.is_ascii_uppercase() {
            if let Some((label_end, end)) = token_at(msg, i) {
                flush!(i);
                let label = String::from_utf8_lossy(&msg[i..label_end]).into_owned();
                shape.push_str(&format!("‹{label}›"));
                pattern.push_str(&format!("{label}_[0-9a-f]+"));
                i = end;
                lit = i;
                continue;
            }
        }
        if boundary && b.is_ascii_hexdigit() {
            let mut j = i;
            while j < msg.len() && msg[j].is_ascii_hexdigit() {
                j += 1;
            }
            let run = &msg[i..j];
            let word_end = !msg.get(j).is_some_and(|c| c.is_ascii_alphanumeric());
            if word_end && run.len() >= 12 && run.iter().any(u8::is_ascii_digit) && run.iter().any(u8::is_ascii_alphabetic) {
                flush!(i);
                shape.push_str("‹hex›");
                pattern.push_str("[0-9a-fA-F]+");
                i = j;
                lit = i;
                continue;
            }
        }
        if b.is_ascii_digit() {
            flush!(i);
            let mut j = i;
            while j < msg.len() && msg[j].is_ascii_digit() {
                j += 1;
            }
            shape.push('0');
            pattern.push_str("\\d+");
            i = j;
            lit = i;
            continue;
        }
        // Avancer d'un caractère UTF-8 entier.
        i += 1;
        while i < msg.len() && (msg[i] & 0xC0) == 0x80 {
            i += 1;
        }
    }
    flush!(i.min(msg.len()));
    (shape, pattern)
}

#[derive(Default)]
struct ShapeAgg {
    pattern: String,
    count: u64,
    bytes: u64,
    level: &'static str,
    kind: &'static str,
    filtered: u64,
    filtered_by: Option<usize>,
}

#[derive(Default)]
struct KeyAgg {
    count: u64,
    replaced: u64,
    distinct: HashSet<u64>,
    shapes: HashMap<String, u64>,
}

#[derive(Default)]
struct Partial {
    entries: u64,
    bytes: u64,
    filtered_entries: u64,
    filtered_bytes: u64,
    shapes: HashMap<String, ShapeAgg>,
    keys: HashMap<String, KeyAgg>,
}

fn fnv(v: &[u8]) -> u64 {
    v.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3))
}

fn profile_batch(engine: &Engine, entries: &[Entry], sc: &mut Scratch, spans: &mut Spans) -> Partial {
    let tpl = engine.template();
    let format = engine.format();
    let mut p = Partial::default();
    let mut stats = engine.new_stats();
    let mut text = Vec::new();
    for entry in entries {
        text.clear();
        let filter = engine.matching_filter(entry);
        // Une entrée supprimée par une règle `drop_entry` n'a pas de texte : elle est ignorée.
        if engine.process_unfiltered(entry, sc, &mut text, &mut stats) == Outcome::Dropped {
            continue;
        }
        let bytes = (text.len() + entry.source.len() + 3) as u64;
        p.entries += 1;
        p.bytes += bytes;
        let header_len = memchr::memchr(b'\n', &text).unwrap_or(text.len());
        let header = &text[..header_len];
        let start = format.message_start(header).min(header.len());
        let (shape, mut pattern) = shape_of(&header[start..]);
        // Le filtre porte sur toute la ligne d'en-tête : on l'ancre après l'horodatage et le
        // niveau, ou après `haproxy[<pid>]: ` quand l'en-tête syslog est gardé.
        let anchor = match start {
            0 => "^",
            _ if header[..start].ends_with(b"]: ") => "\\]: ",
            _ => "\\] +",
        };
        pattern.insert_str(0, anchor);
        let agg = p.shapes.entry(shape).or_default();
        agg.pattern = pattern;
        agg.count += 1;
        agg.bytes += bytes;
        agg.level = entry.level.map_or("", |l| l.as_str());
        agg.kind = entry.kind.as_str();
        if filter.is_some() {
            agg.filtered += 1;
            agg.filtered_by = filter;
            p.filtered_entries += 1;
            p.filtered_bytes += bytes;
            continue;
        }
        let req = if tpl.extractors.http_request { format.request(header) } else { None };
        extract::run(&text, header_len, req.as_ref(), &tpl.extractors, spans);
        for s in spans.items.iter().filter(|s| s.end > s.start) {
            let v = &text[s.start as usize..s.end as usize];
            let key = match p.keys.get_mut(std::str::from_utf8(spans.path(s)).unwrap_or("")) {
                Some(k) => k,
                None => p.keys.entry(String::from_utf8_lossy(spans.path(s)).into_owned()).or_default(),
            };
            key.count += 1;
            if is_replaced(v) {
                key.replaced += 1;
            } else {
                if key.shapes.len() < VALUE_SHAPES_CAP * 4 {
                    *key.shapes.entry(mask_value(v)).or_default() += 1;
                }
                if key.distinct.len() < DISTINCT_CAP {
                    // Une empreinte seulement : la valeur n'est ni gardée ni rendue.
                    key.distinct.insert(fnv(v));
                }
            }
        }
    }
    p
}

const OTHER_SHAPES: &str = "(autres formes, trop nombreuses pour être suivies une à une)";

fn merge(total: &mut Partial, part: Partial, opts: &ProfileOptions) {
    total.entries += part.entries;
    total.bytes += part.bytes;
    total.filtered_entries += part.filtered_entries;
    total.filtered_bytes += part.filtered_bytes;
    for (shape, a) in part.shapes {
        let full = total.shapes.len() >= opts.max_shapes && !total.shapes.contains_key(&shape);
        let slot = total.shapes.entry(if full { OTHER_SHAPES.to_string() } else { shape }).or_default();
        slot.count += a.count;
        slot.bytes += a.bytes;
        if !full {
            slot.pattern = a.pattern;
            slot.level = a.level;
            slot.kind = a.kind;
            slot.filtered += a.filtered;
            if a.filtered_by.is_some() {
                slot.filtered_by = a.filtered_by;
            }
        }
    }
    for (path, a) in part.keys {
        if total.keys.len() >= opts.max_keys && !total.keys.contains_key(&path) {
            continue;
        }
        let slot = total.keys.entry(path).or_default();
        slot.count += a.count;
        slot.replaced += a.replaced;
        for (s, n) in a.shapes {
            *slot.shapes.entry(s).or_default() += n;
        }
        for h in a.distinct {
            if slot.distinct.len() < DISTINCT_CAP {
                slot.distinct.insert(h);
            }
        }
    }
}

/// Profile `input` avec le template du moteur. `progress` reçoit le nombre d'entrées vues.
pub fn profile<R: Read + Send>(input: R, engine: &Engine, opts: &ProfileOptions, cancel: &AtomicBool, progress: &mut dyn FnMut(u64)) -> Result<Profile> {
    let group = rayon::current_num_threads().max(1) * 2;
    let (tx, rx) = crossbeam_channel::bounded::<Item>(group);
    let mut total = Partial::default();
    let mut input_error = None;
    std::thread::scope(|scope| -> Result<()> {
        scope.spawn(move || produce(input, engine, tx, cancel, 4 << 20));
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
                    Item::InputError(msg) => input_error = Some(msg),
                }
                if batches.len() < group {
                    next = rx.try_recv().ok();
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }
            let parts: Vec<Partial> =
                batches.par_iter().map_init(|| (Scratch::default(), Spans::default()), |(sc, sp), b| profile_batch(engine, b, sc, sp)).collect();
            for part in parts {
                merge(&mut total, part, opts);
            }
            progress(total.entries);
        }
        Ok(())
    })?;
    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled);
    }

    let tpl = engine.template();
    let shapes_total = total.shapes.len() as u64;
    let mut shapes: Vec<ShapeStat> = total
        .shapes
        .into_iter()
        .map(|(shape, a)| ShapeStat {
            shape,
            pattern: a.pattern,
            count: a.count,
            bytes: a.bytes,
            level: a.level.to_string(),
            kind: a.kind.to_string(),
            filtered_count: a.filtered,
            filtered_by: a.filtered_by.map(|i| tpl.filters[i].id.clone()),
        })
        .collect();
    shapes.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.shape.cmp(&b.shape)));
    shapes.truncate(opts.top_shapes);

    let keys_total = total.keys.len() as u64;
    let mut keys: Vec<KeyStat> = total
        .keys
        .into_iter()
        .map(|(path, a)| {
            let mut value_shapes: Vec<(String, u64)> = a.shapes.into_iter().collect();
            value_shapes.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
            value_shapes.truncate(6);
            KeyStat { path, count: a.count, replaced: a.replaced, distinct: a.distinct.len() as u64, distinct_capped: a.distinct.len() >= DISTINCT_CAP, shapes: value_shapes }
        })
        .collect();
    // Les clés qui gardent le plus de valeurs en clair d'abord : ce sont elles à examiner.
    keys.sort_by(|a, b| (b.count - b.replaced).cmp(&(a.count - a.replaced)).then_with(|| a.path.cmp(&b.path)));
    keys.truncate(opts.top_keys);

    Ok(Profile {
        entries: total.entries,
        bytes: total.bytes,
        filtered_entries: total.filtered_entries,
        filtered_bytes: total.filtered_bytes,
        shapes_total,
        shapes,
        keys_total,
        keys,
        input_error,
    })
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;
    use crate::engine::EngineOptions;
    use crate::template::library::Library;
    use crate::template::testing::TEST_KEY;
    use std::sync::Arc;

    fn shape(s: &str) -> (String, String) {
        shape_of(s.as_bytes())
    }

    #[test]
    fn shapes_mask_numbers_strings_tokens_and_hex() {
        assert_eq!(shape("Sent 200 in 9ms\tPOST /api/x").0, "Sent 0 in 0ms\tPOST /api/x");
        assert_eq!(shape("for 900398190 which goes from 'waiting_prep' to 'in_prep'").0, "for 0 which goes from '…' to '…'");
        assert_eq!(shape("owner EMAIL_e3236363 not found on IP_ad3bba6c:443").0, "owner ‹EMAIL› not found on ‹IP›:0");
        assert_eq!(shape("stock for id \"ETAM_0063_42\" key 6dfe6859b89a20081966 [SECRET]").0, "stock for id \"…\" key ‹hex› [SECRET]");
        assert_eq!(shape("it's 5 o'clock").0, "it'…'clock");
        assert_eq!(shape("unclosed \"quote 12").0, "unclosed \"quote 0");
    }

    #[test]
    fn the_pattern_matches_what_produced_the_shape_and_its_siblings() {
        for (a, b, other) in [
            ("Sent 200 in 9ms\tPOST /api/x", "Sent 404 in 1532ms\tPOST /api/x", "Sent 200 in 9ms\tGET /api/x"),
            ("Execute action 'check_routing' (bypass state/transitions) for 9001 which goes", "Execute action 'trigger' (bypass state/transitions) for 12 which goes", "Execute action check for 1"),
            ("owner EMAIL_e3236363 not found [x] {a: 1} a|b $", "owner EMAIL_00000000ff not found [x] {a: 9} a|b $", "owner USER_e3236363 not found [x] {a: 1} a|b $"),
            ("[gts]: ticking é 1.5", "[gts]: ticking é 22.75", "[gts]: tocking é 1.5"),
        ] {
            let (shape_a, pattern) = shape(a);
            let re = regex::bytes::Regex::new(&format!("^{pattern}")).unwrap_or_else(|e| panic!("{pattern} : {e}"));
            assert!(re.is_match(a.as_bytes()), "{pattern} ne reconnaît pas {a}");
            assert!(re.is_match(b.as_bytes()), "{pattern} ne reconnaît pas {b}");
            assert!(!re.is_match(other.as_bytes()), "{pattern} reconnaît à tort {other}");
            assert_eq!(shape_a, shape(b).0);
        }
    }

    #[test]
    fn replaced_values_and_masks() {
        assert!(is_replaced(b"EMAIL_e3236363") && is_replaced(b"CUSTOMERID_2a2c43c0aa") && is_replaced(b"[ADDRESS]"));
        assert!(!is_replaced(b"ETAM_0063") && !is_replaced(b"Jean") && !is_replaced(b"[info]") && !is_replaced(b"EMAIL_e3236363 "));
        assert_eq!(mask_value(b"Jean"), "Aa+");
        assert_eq!(mask_value(b"75000"), "0+");
        assert_eq!(mask_value(b"jean.dupont@example.com"), "a+*a+*a+*a+");
    }

    #[cfg(logano_templates)]
    #[test]
    fn profile_ranks_shapes_marks_filtered_ones_and_inventories_keys() {
        let lib = Library::builtin();
        let engine = Engine::new(Arc::new(lib.compile("etam/services").unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap();
        let mut input = String::new();
        for i in 0..50 {
            input.push_str(&format!("s1.kbrw.fr  10:00:{:02}.000 [info]  The old stock value is the same as the new stock value for id \"ETAM_{i}\"\n", i % 60));
        }
        for i in 0..20 {
            input.push_str(&format!("s1.kbrw.fr  10:01:00.{i:03} [info]  order {i} synced for store \"S{i}\"\n"));
            input.push_str(&format!("s1.kbrw.fr  10:01:01.{i:03} [debug] x %{{properties: [%{{name: :firstName, value: \"Prenom{i}\"}}, %{{name: :basket, value: \"B{i}\"}}], nickname: \"Nick{i}\"}}\n"));
        }
        let p = profile(input.as_bytes(), &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(p.entries, 90);
        assert_eq!(p.filtered_entries, 50);
        let stock = p.shapes.iter().find(|s| s.shape.starts_with("The old stock value")).unwrap();
        assert_eq!((stock.count, stock.filtered_count, stock.filtered_by.as_deref()), (50, 50, Some("etam/services:stock-unchanged")));
        let synced = p.shapes.iter().find(|s| s.shape == "order 0 synced for store \"…\"").unwrap();
        assert_eq!((synced.count, synced.filtered_count, synced.filtered_by.as_deref(), synced.level.as_str()), (20, 0, None, "info"));
        assert!(regex::bytes::Regex::new(&synced.pattern).unwrap().is_match(b"10:01:00.007 [info]  order 7 synced for store \"S7\""));

        // Une forme filtrée en partie seulement : mêmes mots, seule la chaîne entre apostrophes
        // (masquée dans la forme) décide du filtre.
        let mixed = "s1.kbrw.fr  10:02:00.000 [info]  Execute action 'check_routing' (bypass state/transitions) for 1 which goes from 'waiting_prep' to 'waiting_prep'\n\
s1.kbrw.fr  10:02:01.000 [info]  Execute action 'check_routing' (bypass state/transitions) for 2 which goes from 'waiting_prep' to 'in_prep'\n";
        let m = profile(mixed.as_bytes(), &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(m.shapes.len(), 1);
        assert_eq!((m.shapes[0].count, m.shapes[0].filtered_count, m.shapes[0].filtered_by.as_deref()), (2, 1, Some("etam/services:check-routing-noop")));

        let key = |path: &str| p.keys.iter().find(|k| k.path == path).unwrap_or_else(|| panic!("clé {path} absente : {:?}", p.keys.iter().map(|k| &k.path).collect::<Vec<_>>()));
        // Remplacée partout : rien en clair.
        assert_eq!((key("properties.firstname").count, key("properties.firstname").replaced), (20, 20));
        // Non couvertes : valeurs en clair, formes masquées, jamais la valeur.
        let nick = key("nickname");
        assert_eq!((nick.count, nick.replaced, nick.distinct), (20, 0, 20));
        assert_eq!(nick.shapes[0].0, "Aa+0");
        assert_eq!(key("properties.basket").replaced, 0);
        // Les clés qui gardent le plus de valeurs en clair viennent d'abord.
        assert!(p.keys[0].count > p.keys[0].replaced);
        assert!(!format!("{p:?}").contains("Prenom7") && !format!("{p:?}").contains("Nick7"));
    }

    #[cfg(logano_templates)]
    #[test]
    fn profile_inventories_haproxy_fields_and_query_parameters() {
        let lib = Library::builtin();
        let engine = Engine::new(Arc::new(lib.compile("kbrw/haproxy").unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap();
        let input = concat!(include_str!("../../../corpus/kbrw-haproxy/prompt-examples.in.log"), include_str!("../../../corpus/kbrw-haproxy/variants.in.log"));
        let p = profile(input.as_bytes(), &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
        // 15 lignes ; le ping et le scan refusé sont retirés par les filtres du template.
        assert_eq!((p.entries, p.filtered_entries), (15, 2));
        let mut kinds: Vec<&str> = p.shapes.iter().map(|s| s.kind.as_str()).collect();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds, vec!["http", "other", "tcp", "tls_error"]);

        let key = |path: &str| {
            let k = p.keys.iter().find(|k| k.path == path).unwrap_or_else(|| panic!("clé {path} absente : {:?}", p.keys.iter().map(|k| &k.path).collect::<Vec<_>>()));
            (k.count, k.replaced)
        };
        // 13 entrées gardées : 10 clients publics remplacés, 3 IPv6 internes en clair.
        assert_eq!(key("haproxy.client_ip"), (13, 10));
        assert_eq!(key("haproxy.client_port"), (13, 0));
        // Les lignes TCP, les erreurs TLS et la ligne coupée n'ont pas de statut.
        assert_eq!(key("haproxy.status"), (8, 0));
        assert_eq!(key("url.query.samlresponse"), (1, 1));
        assert_eq!(key("url.query.password"), (1, 1));
        assert_eq!(key("url.query.user"), (1, 1));
        assert_eq!(key("url.query.state"), (1, 0));
        assert_eq!(key("haproxy.hds.0"), (4, 0));
        let dump = format!("{p:?}");
        assert!(!dump.contains("198.51.100") && !dump.contains("jean.dupont") && !dump.contains("hunter22"));
    }

    #[cfg(logano_templates)]
    #[test]
    fn the_filter_pattern_is_anchored_after_the_kept_syslog_header() {
        let mut lib = Library::builtin();
        lib.add_str("[template]\nid='t/x'\nname='x'\nversion='1.0.0'\nschema_version=1\nformat='haproxy_syslog'\n").unwrap();
        let engine = Engine::new(Arc::new(lib.compile("t/x").unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap();
        let line = "h.kbrw.fr  2026-11-09T00:00:06+00:00 h.kbrw.fr haproxy[227]: Proxy etam_sb_admin-local_ipv6-8080 started.\n";
        let p = profile(line.as_bytes(), &engine, &ProfileOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(p.shapes.len(), 1);
        assert_eq!(p.shapes[0].shape, "Proxy etam_sb_admin-local_ipv0-0 started.");
        assert_eq!(p.shapes[0].kind, "other");
        let re = regex::bytes::Regex::new(&p.shapes[0].pattern).unwrap();
        assert!(re.is_match(b"2026-11-09T00:00:07+00:00 h.kbrw.fr haproxy[9]: Proxy etam_sb_admin-local_ipv6-8081 started."), "{}", p.shapes[0].pattern);
    }
}

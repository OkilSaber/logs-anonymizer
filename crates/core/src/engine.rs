//! Traitement d'une entrée : filtres, extraction, règles, résolution, reconstruction,
//! filet de sécurité.

use crate::detect::{detect, DetectorId, Finding};
use crate::entry::Entry;
use crate::error::Result;
use crate::extract::{self, Spans};
use crate::format::{make_format_with, Format};
use crate::netaddr;
use crate::overlap::{self, Cand};
use crate::pseudonym::Pseudonymizer;
use crate::rules::{CompiledTemplate, Selector};
use crate::safety::default_action;
use crate::stats::{SafetyFinding, Stats, MAX_FINDINGS};
use crate::strategy::{apply, Action, Normalize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafetyAction {
    /// Ce que le filet trouve est remplacé (défaut).
    Replace,
    /// Ce que le filet trouve est seulement signalé : la sortie n'est pas sûre tant
    /// que les trouvailles ne sont pas traitées.
    Report,
}

#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// Clé du run pour les jetons.
    pub key: [u8; 32],
    pub safety: SafetyAction,
    /// Collecter la table jeton → valeur d'origine.
    pub collect_mapping: bool,
}

impl EngineOptions {
    pub fn with_key(key: [u8; 32]) -> Self {
        EngineOptions { key, safety: SafetyAction::Replace, collect_mapping: false }
    }
}

/// Règle fictive d'un remplacement issu d'une fusion de chevauchements.
const MERGED: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct Edit {
    src: (u32, u32),
    out: (u32, u32),
    rule: u32,
    keep: bool,
}

/// Un remplacement, pour le bac à sable : plages dans le texte brut et dans la sortie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEdit {
    pub src: (usize, usize),
    pub out: (usize, usize),
    /// Id de la règle, ou `filet:<détecteur>` pour le filet de sécurité.
    pub rule: String,
    pub safety: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Trace {
    pub dropped_by: Option<String>,
    pub edits: Vec<TraceEdit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Dropped,
    Kept { modified: bool },
}

/// Tampons réutilisés d'une entrée à l'autre ; un par thread.
#[derive(Default)]
pub struct Scratch {
    spans: Spans,
    findings: Vec<Finding>,
    cands: Vec<Cand>,
    key_cache: HashMap<Vec<u8>, Vec<u32>>,
    out1: Vec<u8>,
    edits: Vec<Edit>,
}

pub struct Engine {
    tpl: Arc<CompiledTemplate>,
    format: Arc<dyn Format>,
    pseudo: Pseudonymizer,
    opts: EngineOptions,
    safety_actions: Vec<Action>,
}

impl Engine {
    pub fn new(tpl: Arc<CompiledTemplate>, opts: EngineOptions) -> Result<Self> {
        let format = make_format_with(tpl.format, tpl.format_cfg)?;
        Ok(Engine {
            pseudo: Pseudonymizer::new(opts.key, opts.collect_mapping),
            safety_actions: DetectorId::ALL.iter().map(|d| default_action(*d)).collect(),
            tpl,
            format,
            opts,
        })
    }

    pub fn template(&self) -> &CompiledTemplate {
        &self.tpl
    }

    pub fn format(&self) -> Arc<dyn Format> {
        self.format.clone()
    }

    pub fn new_stats(&self) -> Stats {
        Stats::sized(self.tpl.rules.len(), self.tpl.filters.len())
    }

    /// Table jeton → valeur d'origine (si `collect_mapping`).
    pub fn mapping(&self) -> Vec<(String, String)> {
        self.pseudo.mapping()
    }

    fn allowed(&self, detector: Option<DetectorId>, normalize: Normalize, value: &[u8]) -> bool {
        let allow = &self.tpl.allow;
        if allow.value(value) {
            return true;
        }
        let ip = |v: &[u8]| netaddr::parse_loose(v).is_some_and(|ip| allow.ip(&ip));
        match detector {
            Some(DetectorId::Email) => allow.email(value),
            Some(d) if d.is_ip() => ip(value),
            Some(_) => false,
            None => match normalize {
                Normalize::Ip => ip(value),
                Normalize::Email => allow.email(value),
                _ => false,
            },
        }
    }

    /// Premier filtre de bruit qui supprimerait cette entrée.
    pub fn matching_filter(&self, entry: &Entry) -> Option<usize> {
        let tpl = &*self.tpl;
        let req = if tpl.needs_request { self.format.request(entry.header()) } else { None };
        tpl.filters.iter().position(|f| f.matches(entry, req.as_ref(), &*self.format))
    }

    /// Traite une entrée. Le texte anonymisé (sans préfixe host) est ajouté à `out`.
    pub fn process(&self, entry: &Entry, sc: &mut Scratch, out: &mut Vec<u8>, stats: &mut Stats, trace: Option<&mut Trace>) -> Outcome {
        self.process_with(entry, sc, out, stats, trace, true)
    }

    /// Comme [`Engine::process`], sans appliquer les filtres de bruit : le profileur a
    /// besoin de la forme anonymisée de toutes les entrées, y compris celles qu'un filtre retire.
    pub fn process_unfiltered(&self, entry: &Entry, sc: &mut Scratch, out: &mut Vec<u8>, stats: &mut Stats) -> Outcome {
        self.process_with(entry, sc, out, stats, None, false)
    }

    fn process_with(
        &self,
        entry: &Entry,
        sc: &mut Scratch,
        out: &mut Vec<u8>,
        stats: &mut Stats,
        mut trace: Option<&mut Trace>,
        apply_filters: bool,
    ) -> Outcome {
        let tpl = &*self.tpl;
        let text = &entry.text[..];
        let header_len = entry.header_len();
        stats.entries_in += 1;
        stats.lines_in += entry.lines as u64;
        stats.bytes_in += text.len() as u64;

        // 1. Filtres de bruit, sur l'en-tête.
        let req = if tpl.needs_request { self.format.request(&text[..header_len]) } else { None };
        for (i, f) in tpl.filters.iter().enumerate().filter(|_| apply_filters) {
            if f.matches(entry, req.as_ref(), &*self.format) {
                stats.filter_hits[i] += 1;
                stats.dropped += 1;
                if let Some(t) = trace.as_deref_mut() {
                    t.dropped_by = Some(f.id.clone());
                }
                return Outcome::Dropped;
            }
        }

        // 2. Structuration paresseuse.
        let Scratch { spans, findings, cands, key_cache, out1, edits } = sc;
        extract::run(text, header_len, req.as_ref(), &tpl.extractors, spans);

        // 3. Candidats.
        cands.clear();
        let mut order = 0u32;
        let mut push = |cands: &mut Vec<Cand>, start: u32, end: u32, rule: u32, quote: bool, field: Option<(u32, u32)>| {
            cands.push(Cand { start, end, prio: tpl.rules[rule as usize].priority, rule, order, quote, field });
            order += 1;
        };
        if !tpl.key_rules.is_empty() {
            for span in spans.items.iter().filter(|s| s.end > s.start) {
                let path = spans.path(span);
                if !key_cache.contains_key(path) {
                    key_cache.insert(path.to_vec(), tpl.key_rules_for(path));
                }
                for &r in &key_cache[path] {
                    let rule = &tpl.rules[r as usize];
                    let value = &text[span.start as usize..span.end as usize];
                    if rule.applies(entry, Some(span.extractor)) && !self.allowed(None, rule.action.normalize(), value) {
                        push(cands, span.start, span.end, r, span.quote, span.field);
                    }
                }
            }
        }
        if let Some(req) = &req {
            let mut caps = Vec::new();
            for &r in &tpl.route_rules {
                let rule = &tpl.rules[r as usize];
                let Selector::Routes { patterns, targets } = &rule.selector else { continue };
                if !rule.applies(entry, None) {
                    continue;
                }
                for p in patterns {
                    caps.clear();
                    if !p.matches(text, req, &mut caps) {
                        continue;
                    }
                    for (name, (s, e)) in &caps {
                        let wanted = targets.as_ref().is_none_or(|t| t.iter().any(|x| x == name));
                        if wanted && !self.allowed(None, rule.action.normalize(), &text[*s..*e]) {
                            push(cands, *s as u32, *e as u32, r, false, None);
                        }
                    }
                    break;
                }
            }
        }
        for &r in &tpl.regex_rules {
            let rule = &tpl.rules[r as usize];
            let Selector::Regex(re) = &rule.selector else { continue };
            if !rule.applies(entry, None) {
                continue;
            }
            for caps in re.captures_iter(text) {
                if let Some(m) = caps.name("v") {
                    if m.end() > m.start() && !self.allowed(None, rule.action.normalize(), m.as_bytes()) {
                        push(cands, m.start() as u32, m.end() as u32, r, false, None);
                    }
                }
            }
        }
        for (det, rule_ids) in &tpl.detector_rules {
            findings.clear();
            detect(*det, text, &tpl.detector_cfg, findings);
            for f in findings.iter() {
                if self.allowed(Some(*det), Normalize::None, &text[f.start as usize..f.end as usize]) {
                    continue;
                }
                for &r in rule_ids {
                    if tpl.rules[r as usize].applies(entry, None) {
                        push(cands, f.start, f.end, r, false, None);
                    }
                }
            }
        }

        if let Some(c) = cands.iter().find(|c| matches!(tpl.rules[c.rule as usize].action, Action::DropEntry)) {
            stats.rule_hits[c.rule as usize] += 1;
            stats.dropped += 1;
            if let Some(t) = trace.as_deref_mut() {
                t.dropped_by = Some(tpl.rules[c.rule as usize].id.clone());
            }
            return Outcome::Dropped;
        }

        // 4. Résolution des chevauchements.
        let accepted = overlap::resolve(
            cands,
            |outer, inner| tpl.rules[outer as usize].keep_inner.contains(&inner),
            |r| !matches!(tpl.rules[r as usize].action, Action::Keep),
            |r| stats.shadowed[r as usize] += 1,
        );

        // 5. Reconstruction en une passe.
        out1.clear();
        edits.clear();
        let mut pos = 0usize;
        for a in &accepted {
            let (mut s, mut e) = (a.cand.start as usize, a.cand.end as usize);
            let action = (!a.merged).then(|| &tpl.rules[a.cand.rule as usize].action);
            let mut drop_field = false;
            if let (Some(Action::DropField), Some((fs, fe))) = (action, a.cand.field) {
                // Le champ entier, avec la virgule et les espaces qui le suivent.
                s = (fs as usize).max(pos);
                e = fe as usize;
                if text.get(e) == Some(&b',') {
                    e += 1;
                    while text.get(e) == Some(&b' ') {
                        e += 1;
                    }
                }
                drop_field = true;
            }
            out1.extend_from_slice(&text[pos..s]);
            pos = e;
            let mut record = |out1: &Vec<u8>, src: (usize, usize), o_start: usize, rule: u32, keep: bool| {
                edits.push(Edit { src: (src.0 as u32, src.1 as u32), out: (o_start as u32, out1.len() as u32), rule, keep });
            };
            let o_start = out1.len();
            match action {
                None => {
                    out1.extend_from_slice(b"[REDACTED]");
                    stats.merged += 1;
                    record(out1, (s, e), o_start, MERGED, false);
                }
                Some(Action::Keep) => {
                    out1.extend_from_slice(&text[s..e]);
                    record(out1, (s, e), o_start, a.cand.rule, true);
                }
                Some(Action::DropField) if drop_field => {
                    stats.rule_hits[a.cand.rule as usize] += 1;
                    record(out1, (s, e), o_start, a.cand.rule, false);
                }
                Some(action) => {
                    if a.cand.quote {
                        out1.push(b'"');
                    }
                    // Fragments de la règle englobante et trous des règles autorisées à la percer.
                    let mut p = s;
                    for h in &a.holes {
                        let (hs, he) = (h.start as usize, h.end as usize);
                        if hs > p {
                            let o = out1.len();
                            apply(action, &text[p..hs], &self.pseudo, out1);
                            record(out1, (p, hs), o, a.cand.rule, false);
                        }
                        let o = out1.len();
                        apply(&tpl.rules[h.rule as usize].action, &text[hs..he], &self.pseudo, out1);
                        record(out1, (hs, he), o, h.rule, false);
                        stats.rule_hits[h.rule as usize] += 1;
                        p = he;
                    }
                    if p < e {
                        let o = out1.len();
                        apply(action, &text[p..e], &self.pseudo, out1);
                        record(out1, (p, e), o, a.cand.rule, false);
                    }
                    if a.cand.quote {
                        out1.push(b'"');
                    }
                    stats.rule_hits[a.cand.rule as usize] += 1;
                }
            }
        }
        out1.extend_from_slice(&text[pos..]);
        let modified_by_rules = edits.iter().any(|e| !e.keep);

        // 6. Filet de sécurité, sur la sortie.
        let out_base = out.len();
        let safety = self.safety_net(entry, out1, edits, findings, out, stats);

        if let Some(t) = trace {
            build_trace(tpl, edits, &safety, t);
        }
        stats.entries_out += 1;
        stats.bytes_out += (out.len() - out_base) as u64;
        let modified = modified_by_rules || safety.iter().any(|s| s.replaced);
        if modified {
            stats.modified += 1;
        }
        Outcome::Kept { modified }
    }

    /// Relance tous les détecteurs sur la sortie des règles. Ce qui reste est remplacé
    /// (ou seulement signalé) ; le résultat final est ajouté à `out`.
    fn safety_net(&self, entry: &Entry, out1: &[u8], edits: &[Edit], findings: &mut Vec<Finding>, out: &mut Vec<u8>, stats: &mut Stats) -> Vec<SafetyEdit> {
        let tpl = &*self.tpl;
        findings.clear();
        for det in DetectorId::ALL {
            detect(det, out1, &tpl.detector_cfg, findings);
        }
        findings.retain(|f| {
            let touches = |e: &Edit| e.out.0 < f.end && f.start < e.out.1;
            // Ce qu'une règle a déjà produit n'est pas re-détecté ; une valeur gardée
            // (`keep`) n'est protégée que des détecteurs à faux positifs.
            !edits.iter().any(|e| touches(e) && (!e.keep || f.detector.weak()))
                && !self.allowed(Some(f.detector), Normalize::None, &out1[f.start as usize..f.end as usize])
        });
        if findings.is_empty() {
            out.extend_from_slice(out1);
            return Vec::new();
        }
        // Les classes certaines d'abord, puis la plus longue ; sans chevauchement.
        findings.sort_by(|a, b| a.detector.weak().cmp(&b.detector.weak()).then((b.end - b.start).cmp(&(a.end - a.start))).then(a.start.cmp(&b.start)));
        let mut taken: Vec<Finding> = Vec::with_capacity(findings.len());
        for f in findings.iter() {
            if !taken.iter().any(|t| t.start < f.end && f.start < t.end) {
                taken.push(*f);
            }
        }
        taken.sort_by_key(|f| f.start);

        let replace = self.opts.safety == SafetyAction::Replace;
        let base = out.len();
        let mut result = Vec::with_capacity(taken.len());
        let mut pos = 0usize;
        for f in &taken {
            let (s, e) = (f.start as usize, f.end as usize);
            out.extend_from_slice(&out1[pos..s]);
            let o = out.len() - base;
            if replace {
                apply(&self.safety_actions[f.detector.index()], &out1[s..e], &self.pseudo, out);
            } else {
                out.extend_from_slice(&out1[s..e]);
            }
            result.push(SafetyEdit { out1: (s, e), out: (o, out.len() - base), detector: f.detector, replaced: replace });
            stats.safety_hits[f.detector.index()] += 1;
            pos = e;
        }
        out.extend_from_slice(&out1[pos..]);

        for s in &result {
            if stats.findings.len() >= MAX_FINDINGS {
                break;
            }
            // L'extrait vient de la sortie finale : en mode `replace` il ne contient que des jetons.
            let context = if replace {
                let final_out = &out[base..];
                let from = floor_boundary(final_out, s.out.0.saturating_sub(40));
                let to = ceil_boundary(final_out, (s.out.1 + 40).min(final_out.len()));
                String::from_utf8_lossy(&final_out[from..to]).replace('\n', " ⏎ ")
            } else {
                String::new()
            };
            stats.findings.push(SafetyFinding {
                detector: s.detector.as_str(),
                source: entry.source.to_string(),
                line_no: entry.line_no,
                context,
                replaced: replace,
            });
        }
        result
    }
}

#[derive(Clone, Copy, Debug)]
struct SafetyEdit {
    /// Plage dans la sortie des règles.
    out1: (usize, usize),
    /// Plage dans la sortie finale.
    out: (usize, usize),
    detector: DetectorId,
    replaced: bool,
}

fn floor_boundary(b: &[u8], mut i: usize) -> usize {
    while i > 0 && i < b.len() && (b[i] & 0xC0) == 0x80 {
        i -= 1;
    }
    i.min(b.len())
}

fn ceil_boundary(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] & 0xC0) == 0x80 {
        i += 1;
    }
    i
}

/// Reporte les remplacements des deux passes dans les coordonnées du texte brut et de
/// la sortie finale.
fn build_trace(tpl: &CompiledTemplate, edits: &[Edit], safety: &[SafetyEdit], t: &mut Trace) {
    // Décalage sortie des règles → sortie finale, avant une position donnée.
    let shift2 = |pos: usize| -> isize {
        safety.iter().filter(|s| s.out1.1 <= pos).map(|s| (s.out.1 - s.out.0) as isize - (s.out1.1 - s.out1.0) as isize).sum()
    };
    // Décalage sortie des règles → texte brut, avant une position donnée.
    let shift1 = |pos: usize| -> isize {
        edits.iter().filter(|e| e.out.1 as usize <= pos).map(|e| (e.src.1 - e.src.0) as isize - (e.out.1 - e.out.0) as isize).sum()
    };
    for e in edits.iter().filter(|e| !e.keep) {
        let d = shift2(e.out.0 as usize);
        t.edits.push(TraceEdit {
            src: (e.src.0 as usize, e.src.1 as usize),
            out: ((e.out.0 as isize + d) as usize, (e.out.1 as isize + d) as usize),
            rule: if e.rule == MERGED { "fusion de chevauchements".to_string() } else { tpl.rules[e.rule as usize].id.clone() },
            safety: false,
        });
    }
    for s in safety {
        let d = shift1(s.out1.0);
        t.edits.push(TraceEdit {
            src: ((s.out1.0 as isize + d) as usize, (s.out1.1 as isize + d) as usize),
            out: s.out,
            rule: format!("filet:{}", s.detector.as_str()),
            safety: true,
        });
    }
    t.edits.sort_by_key(|e| e.src.0);
}

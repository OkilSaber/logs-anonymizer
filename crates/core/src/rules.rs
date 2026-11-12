//! Template compilé : ce que le moteur exécute.

use crate::assemble::AssembleOptions;
use crate::detect::{DetectorConfig, DetectorId};
use crate::entry::{Entry, EntryKind, Level};
use crate::error::{CoreError, Result};
use crate::extract::{ExtractorId, ExtractorSet};
use crate::format::{make_format_with, Format, FormatConfig, FormatKind};
use crate::glob::glob_match;
use crate::http::{Request, RoutePattern};
use crate::netaddr::Cidr;
use crate::strategy::{Action, Mask, Normalize};
use crate::template::library::Resolved;
use crate::template::model::{Allowlist, FilterDef, RuleDef};
use regex::bytes::{Regex, RegexBuilder};
use std::net::IpAddr;

/// Priorités par défaut selon le sélecteur.
pub const PRIO_KEY: i32 = 200;
pub const PRIO_REGEX: i32 = 150;
pub const PRIO_DETECTOR: i32 = 100;

const REGEX_SIZE_LIMIT: usize = 1 << 20;
const MAX_RULES: usize = 2000;

#[derive(Clone, Debug)]
enum KeySeg {
    Glob(Vec<u8>),
    AnyMany,
}

/// Motif de clé : correspond à une suite contiguë de segments du chemin
/// (`customername` attrape `billingaddress.customername` ; `*address` attrape
/// toutes les feuilles sous `shipping_address`). `$.` ancre à la racine.
#[derive(Clone, Debug)]
pub struct KeyPattern {
    anchored: bool,
    segs: Vec<KeySeg>,
}

impl KeyPattern {
    pub fn parse(s: &str) -> Option<Self> {
        let lower = s.trim().to_ascii_lowercase();
        let (anchored, body) = match lower.strip_prefix("$.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        if body.is_empty() {
            return None;
        }
        let segs = body
            .split('.')
            .map(|p| if p == "**" { KeySeg::AnyMany } else { KeySeg::Glob(p.as_bytes().to_vec()) })
            .collect::<Vec<_>>();
        segs.iter().all(|s| !matches!(s, KeySeg::Glob(g) if g.is_empty())).then_some(KeyPattern { anchored, segs })
    }

    pub fn matches(&self, path: &[&[u8]]) -> bool {
        fn from(segs: &[KeySeg], path: &[&[u8]]) -> bool {
            match segs.first() {
                None => true,
                Some(KeySeg::AnyMany) => (0..=path.len()).any(|k| from(&segs[1..], &path[k..])),
                Some(KeySeg::Glob(g)) => !path.is_empty() && glob_match(g, path[0]) && from(&segs[1..], &path[1..]),
            }
        }
        if self.anchored {
            from(&self.segs, path)
        } else {
            (0..path.len()).any(|i| from(&self.segs, &path[i..]))
        }
    }
}

#[derive(Debug)]
pub enum Selector {
    Keys(Vec<KeyPattern>),
    Routes { patterns: Vec<RoutePattern>, targets: Option<Vec<String>> },
    Regex(Regex),
    Detector(DetectorId),
}

#[derive(Debug)]
pub struct CompiledRule {
    /// Id qualifié : `<template d'origine>:<id>`.
    pub id: String,
    pub priority: i32,
    pub selector: Selector,
    pub action: Action,
    /// Indices des règles autorisées à percer ce remplacement.
    pub keep_inner: Vec<u32>,
    pub extractors: Option<Vec<ExtractorId>>,
    pub kinds: Option<Vec<EntryKind>>,
    pub levels: Option<Vec<Level>>,
}

impl CompiledRule {
    pub fn applies(&self, entry: &Entry, extractor: Option<ExtractorId>) -> bool {
        self.kinds.as_ref().is_none_or(|k| k.contains(&entry.kind))
            && self.levels.as_ref().is_none_or(|l| entry.level.is_some_and(|lv| l.contains(&lv)))
            && match (&self.extractors, extractor) {
                (Some(list), Some(x)) => list.contains(&x),
                _ => true,
            }
    }
}

#[derive(Debug)]
pub struct CompiledFilter {
    pub id: String,
    kinds: Option<Vec<EntryKind>>,
    levels: Option<Vec<Level>>,
    header: Option<Regex>,
    routes: Option<Vec<RoutePattern>>,
    /// Champs d'en-tête du format : chacun doit valoir l'une des valeurs listées.
    fields: Vec<(String, Vec<Vec<u8>>)>,
}

impl CompiledFilter {
    pub fn needs_request(&self) -> bool {
        self.routes.is_some()
    }

    /// Toutes les conditions présentes doivent être vraies. `req` est la requête de
    /// l'entrée et `format` lit ses champs d'en-tête (conditions `where`).
    pub fn matches(&self, entry: &Entry, req: Option<&Request>, format: &dyn Format) -> bool {
        if self.kinds.as_ref().is_some_and(|k| !k.contains(&entry.kind)) {
            return false;
        }
        if self.levels.as_ref().is_some_and(|l| !entry.level.is_some_and(|lv| l.contains(&lv))) {
            return false;
        }
        for (name, values) in &self.fields {
            match format.field(entry.header(), name) {
                Some(v) if values.iter().any(|x| x == v) => {}
                _ => return false,
            }
        }
        if self.header.as_ref().is_some_and(|re| !re.is_match(entry.header())) {
            return false;
        }
        if let Some(routes) = &self.routes {
            let Some(req) = req else { return false };
            let mut caps = Vec::new();
            if !routes.iter().any(|p| p.matches(&entry.text, req, &mut caps)) {
                return false;
            }
        }
        true
    }
}

/// Allowlist compilée.
#[derive(Debug, Default)]
pub struct Allow {
    pub domains: Vec<String>,
    cidrs: Vec<Cidr>,
    emails: Vec<Vec<u8>>,
    values: Vec<Vec<u8>>,
}

impl Allow {
    pub fn ip(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    pub fn email(&self, value: &[u8]) -> bool {
        if self.emails.is_empty() {
            return false;
        }
        let v = value.trim_ascii().to_ascii_lowercase();
        self.emails.iter().any(|g| glob_match(g, &v))
    }

    pub fn value(&self, value: &[u8]) -> bool {
        self.values.iter().any(|g| glob_match(g, value))
    }
}

/// Déduplication des entrées identiques consécutives d'une même source.
#[derive(Clone, Debug)]
pub struct Dedup {
    pub id: String,
    /// Parties ignorées dans la comparaison de deux entrées.
    pub ignore_timestamp: bool,
    pub ignore_pid: bool,
    pub ignore_reference: bool,
}

#[derive(Debug)]
pub struct CompiledTemplate {
    pub id: String,
    pub name: String,
    pub version: String,
    pub chain: Vec<(String, String)>,
    pub format: FormatKind,
    pub format_cfg: FormatConfig,
    pub assemble: AssembleOptions,
    pub extractors: ExtractorSet,
    pub detector_cfg: DetectorConfig,
    pub filters: Vec<CompiledFilter>,
    pub dedup: Option<Dedup>,
    pub rules: Vec<CompiledRule>,
    pub allow: Allow,
    /// Éléments du template reconnus mais pas encore exécutés par cette version du moteur.
    pub warnings: Vec<String>,
    pub key_rules: Vec<u32>,
    pub route_rules: Vec<u32>,
    pub regex_rules: Vec<u32>,
    /// Détecteurs utilisés par des règles, avec les règles concernées.
    pub detector_rules: Vec<(DetectorId, Vec<u32>)>,
    pub needs_request: bool,
}

fn parse_list<T>(id: &str, what: &str, list: &Option<Vec<String>>, parse: impl Fn(&str) -> Option<T>) -> Result<Option<Vec<T>>> {
    let Some(list) = list else { return Ok(None) };
    list.iter()
        .map(|s| parse(s).ok_or_else(|| CoreError::template(id, format!("{what} inconnu : « {s} »"))))
        .collect::<Result<Vec<T>>>()
        .map(Some)
}

fn compile_regex(id: &str, what: &str, src: &str) -> Result<Regex> {
    RegexBuilder::new(src)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| CoreError::template(id, format!("{what} : regex invalide ou trop coûteuse : {e}")))
}

fn compile_action(id: &str, rid: &str, def: &RuleDef, detector: Option<DetectorId>) -> Result<Action> {
    let err = |m: String| CoreError::template(id, format!("règle « {rid} » : {m}"));
    let strategy = def.strategy.as_deref().ok_or_else(|| err("strategy manquante".into()))?;
    let normalize = match &def.normalize {
        Some(n) => Normalize::parse(n).ok_or_else(|| err(format!("normalize inconnu : « {n} »")))?,
        None => match detector {
            Some(DetectorId::Email) => Normalize::Email,
            Some(d) if d.is_ip() => Normalize::Ip,
            Some(DetectorId::Phone) => Normalize::Digits,
            _ => Normalize::Trim,
        },
    };
    let label_ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    Ok(match strategy {
        "pseudonymize" => {
            let token = def.token.clone().ok_or_else(|| err("token manquant pour pseudonymize".into()))?;
            if !label_ok(&token) {
                return Err(err(format!("token « {token} » : attendu [A-Z0-9_]+")));
            }
            Action::Pseudonymize { token, normalize }
        }
        "redact" => {
            let label = def.label.clone().unwrap_or_else(|| "REDACTED".to_string());
            if !label_ok(&label) {
                return Err(err(format!("label « {label} » : attendu [A-Z0-9_]+")));
            }
            let preserve_scheme = match def.preserve.as_deref() {
                None => false,
                Some("scheme") => true,
                Some(other) => return Err(err(format!("preserve inconnu : « {other} »"))),
            };
            Action::Redact { label, preserve_scheme }
        }
        "mask_partial" => {
            let m = def.mask.as_deref().ok_or_else(|| err("mask manquant pour mask_partial".into()))?;
            Action::Mask(Mask::parse(m).ok_or_else(|| err(format!("mask inconnu : « {m} »")))?)
        }
        "hash" => {
            let token = def.token.clone().unwrap_or_else(|| "HASH".to_string());
            if !label_ok(&token) {
                return Err(err(format!("token « {token} » : attendu [A-Z0-9_]+")));
            }
            Action::Hash { token }
        }
        "drop_field" => Action::DropField,
        "drop_entry" => Action::DropEntry,
        "keep" => Action::Keep,
        other => return Err(err(format!("strategy inconnue : « {other} »"))),
    })
}

fn compile_rule(id: &str, qid: &str, def: &RuleDef) -> Result<CompiledRule> {
    let err = |m: String| CoreError::template(id, format!("règle « {qid} » : {m}"));
    let selectors = [def.keys.is_some(), def.route.is_some() || def.routes.is_some(), def.regex.is_some(), def.detector.is_some()];
    if selectors.iter().filter(|s| **s).count() != 1 {
        return Err(err("il faut exactement un sélecteur parmi keys, route(s), regex, detector".into()));
    }
    let mut detector = None;
    let (selector, default_prio) = if let Some(keys) = &def.keys {
        let patterns = keys
            .iter()
            .map(|k| KeyPattern::parse(k).ok_or_else(|| err(format!("motif de clé invalide : « {k} »"))))
            .collect::<Result<Vec<_>>>()?;
        if patterns.is_empty() {
            return Err(err("keys est vide".into()));
        }
        (Selector::Keys(patterns), PRIO_KEY)
    } else if def.route.is_some() || def.routes.is_some() {
        let patterns = def
            .route
            .iter()
            .chain(def.routes.iter().flatten())
            .map(|r| RoutePattern::parse(r).map_err(&err))
            .collect::<Result<Vec<_>>>()?;
        if patterns.iter().all(|p| p.names().next().is_none()) {
            return Err(err("la route ne nomme aucun segment à remplacer, par exemple {v}".into()));
        }
        (Selector::Routes { patterns, targets: def.targets.clone() }, PRIO_KEY)
    } else if let Some(src) = &def.regex {
        let re = compile_regex(id, &format!("règle « {qid} »"), src)?;
        if !re.capture_names().flatten().any(|n| n == "v") {
            return Err(err("la regex doit contenir le groupe nommé (?P<v>…), seul remplacé".into()));
        }
        (Selector::Regex(re), PRIO_REGEX)
    } else {
        let name = def.detector.as_deref().unwrap_or_default();
        let d = DetectorId::parse(name).ok_or_else(|| err(format!("détecteur inconnu : « {name} »")))?;
        detector = Some(d);
        (Selector::Detector(d), PRIO_DETECTOR)
    };
    let action = compile_action(id, qid, def, detector)?;
    if def.keep_inner.is_some() && !matches!(action, Action::Redact { .. }) {
        return Err(err("keep_inner n'est permis qu'avec strategy = \"redact\"".into()));
    }
    Ok(CompiledRule {
        id: qid.to_string(),
        priority: def.priority.unwrap_or(default_prio),
        selector,
        action,
        keep_inner: Vec::new(),
        extractors: parse_list(id, "extracteur", &def.extractors, ExtractorId::parse)?,
        kinds: parse_list(id, "type d'entrée", &def.kinds, EntryKind::parse)?,
        levels: parse_list(id, "niveau", &def.levels, |s| Level::parse(s.as_bytes()))?,
    })
}

/// `where = { status = [400, 404], request = ["<BADREQ>"] }` : entiers et chaînes sont
/// comparés comme du texte au champ d'en-tête du format.
fn compile_where(id: &str, qid: &str, def: &FilterDef, format: &dyn Format) -> Result<Vec<(String, Vec<Vec<u8>>)>> {
    let err = |m: String| CoreError::template(id, format!("filtre « {qid} » : {m}"));
    let known = format.field_names();
    let mut fields = Vec::new();
    for (name, values) in def.where_.iter().flatten() {
        if !known.contains(&name.as_str()) {
            let kind = format.kind().as_str();
            return Err(err(if known.is_empty() {
                format!("where : champ « {name} » inconnu, le format {kind} n'expose aucun champ d'en-tête")
            } else {
                format!("where : champ « {name} » inconnu du format {kind} (champs disponibles : {})", known.join(", "))
            }));
        }
        if values.is_empty() {
            return Err(err(format!("where.{name} : liste vide, la condition ne serait jamais vraie")));
        }
        let values = values
            .iter()
            .map(|v| match v {
                toml::Value::String(s) => Ok(s.clone().into_bytes()),
                toml::Value::Integer(n) => Ok(n.to_string().into_bytes()),
                other => Err(err(format!("where.{name} : valeur {other} non prise en charge (attendu un entier ou une chaîne)"))),
            })
            .collect::<Result<Vec<_>>>()?;
        fields.push((name.clone(), values));
    }
    Ok(fields)
}

fn compile_filter(id: &str, qid: &str, def: &FilterDef, format: &dyn Format) -> Result<Option<CompiledFilter>> {
    let err = |m: String| CoreError::template(id, format!("filtre « {qid} » : {m}"));
    match def.action.as_deref().unwrap_or("drop_entry") {
        "drop_entry" => {}
        // Traité à part par l'appelant : ce n'est pas une condition sur une entrée.
        "dedup" => return Ok(None),
        other => return Err(err(format!("action inconnue : « {other} »"))),
    }
    let routes = match &def.routes {
        Some(list) => Some(list.iter().map(|r| RoutePattern::parse(r).map_err(&err)).collect::<Result<Vec<_>>>()?),
        None => None,
    };
    let f = CompiledFilter {
        id: qid.to_string(),
        kinds: parse_list(id, "type d'entrée", &def.kinds, EntryKind::parse)?,
        levels: parse_list(id, "niveau", &def.levels, |s| Level::parse(s.as_bytes()))?,
        header: def.header.as_deref().map(|h| compile_regex(id, &format!("filtre « {qid} »"), h)).transpose()?,
        routes,
        fields: compile_where(id, qid, def, format)?,
    };
    if f.kinds.is_none() && f.levels.is_none() && f.header.is_none() && f.routes.is_none() && f.fields.is_empty() {
        return Err(err("aucune condition : il supprimerait toutes les entrées".into()));
    }
    Ok(Some(f))
}

fn compile_allow(id: &str, a: &Allowlist) -> Result<Allow> {
    let cidrs = a
        .cidrs
        .iter()
        .map(|c| Cidr::parse(c).ok_or_else(|| CoreError::template(id, format!("allowlist.cidrs : plage invalide « {c} »"))))
        .collect::<Result<Vec<_>>>()?;
    Ok(Allow {
        domains: a.domains.iter().map(|d| d.to_ascii_lowercase()).collect(),
        cidrs,
        emails: a.emails.iter().map(|e| e.to_ascii_lowercase().into_bytes()).collect(),
        values: a.values.iter().map(|v| v.as_bytes().to_vec()).collect(),
    })
}

impl CompiledTemplate {
    pub fn compile(r: &Resolved) -> Result<Self> {
        let id = r.id.as_str();
        // Plus rien n'est signalé aujourd'hui : tout ce qu'un template peut nommer est exécuté.
        let warnings = Vec::new();
        let format = match &r.format {
            // Un template abstrait est testé avec le format `plain`.
            None => FormatKind::Plain,
            Some(f) => FormatKind::parse(f).ok_or_else(|| CoreError::template(id, format!("format inconnu : « {f} »")))?,
        };
        if r.rules.len() > MAX_RULES {
            return Err(CoreError::template(id, format!("trop de règles ({} > {MAX_RULES})", r.rules.len())));
        }

        let o = &r.options;
        let format_cfg = FormatConfig { compact_header: o.compact_header.unwrap_or(false) };
        let fmt = make_format_with(format, format_cfg)?;
        let defaults = AssembleOptions::default();
        let assemble = AssembleOptions {
            strip_ansi: o.strip_ansi.unwrap_or(defaults.strip_ansi),
            max_entry_lines: o.max_entry_lines.unwrap_or(defaults.max_entry_lines).max(1),
            max_entry_bytes: o.max_entry_bytes.map(|b| b.0 as usize).unwrap_or(defaults.max_entry_bytes).max(1024),
            reorder_window: o.reorder_window.map(|w| w as usize).unwrap_or(defaults.reorder_window).max(1),
            reorder_bytes: defaults.reorder_bytes,
        };

        let mut extractors = ExtractorSet::for_format(format);
        if let Some(enabled) = &r.extractors {
            let ids = enabled
                .iter()
                .map(|s| ExtractorId::parse(s).ok_or_else(|| CoreError::template(id, format!("extracteur inconnu : « {s} »"))))
                .collect::<Result<Vec<_>>>()?;
            for x in ExtractorId::ALL {
                extractors.set(x, ids.contains(&x));
            }
        }
        for (name, table) in &r.extractor_options {
            if ExtractorId::parse(name).is_none() {
                return Err(CoreError::template(id, format!("extractors.options : extracteur inconnu « {name} »")));
            }
            if let Some(d) = table.get("max_depth").and_then(|v| v.as_integer()) {
                extractors.max_depth = extractors.max_depth.min(d.clamp(1, 256) as usize);
            }
        }

        let mut detector_cfg = DetectorConfig::default();
        for (name, table) in &r.detectors {
            if DetectorId::parse(name).is_none() {
                return Err(CoreError::template(id, format!("detectors : détecteur inconnu « {name} »")));
            }
            if name == "high_entropy" {
                if let Some(n) = table.get("min_len").and_then(|v| v.as_integer()) {
                    detector_cfg.entropy_min_len = n.clamp(16, 4096) as usize;
                }
                if let Some(b) = table.get("min_entropy").and_then(|v| v.as_float().or(v.as_integer().map(|i| i as f64))) {
                    detector_cfg.entropy_min_bits = b.clamp(1.0, 8.0) as f32;
                }
            }
        }

        let mut filters = Vec::new();
        let mut dedup = None;
        for (qid, def) in &r.filters {
            if def.enabled == Some(false) {
                continue;
            }
            if def.action.as_deref() == Some("dedup") {
                let ignore = def.ignore.clone().unwrap_or_default();
                if let Some(bad) = ignore.iter().find(|i| !matches!(i.as_str(), "timestamp" | "pid" | "reference")) {
                    return Err(CoreError::template(id, format!("filtre « {qid} » : ignore inconnu « {bad} » (attendu timestamp, pid, reference)")));
                }
                let has = |name: &str| ignore.iter().any(|i| i == name);
                dedup = Some(Dedup { id: qid.clone(), ignore_timestamp: has("timestamp"), ignore_pid: has("pid"), ignore_reference: has("reference") });
            }
            if let Some(f) = compile_filter(id, qid, def, &*fmt)? {
                filters.push(f);
            }
        }

        let mut rules = Vec::new();
        let mut keep_inner_refs = Vec::new();
        for (qid, def) in &r.rules {
            // Une règle désactivée est quand même validée : un template partagé doit être sain.
            let rule = compile_rule(id, qid, def)?;
            if def.enabled == Some(false) {
                continue;
            }
            keep_inner_refs.push(def.keep_inner.clone().unwrap_or_default());
            rules.push(rule);
        }
        for (i, refs) in keep_inner_refs.iter().enumerate() {
            for name in refs {
                match rules.iter().position(|r| r.id == *name) {
                    Some(j) => rules[i].keep_inner.push(j as u32),
                    None if r.rules.iter().any(|(q, _)| q == name) => {}
                    None => return Err(CoreError::template(id, format!("règle « {} » : keep_inner cite une règle inconnue « {name} »", rules[i].id))),
                }
            }
        }

        let mut key_rules = Vec::new();
        let mut route_rules = Vec::new();
        let mut regex_rules = Vec::new();
        let mut detector_rules: Vec<(DetectorId, Vec<u32>)> = Vec::new();
        for (i, rule) in rules.iter().enumerate() {
            let i = i as u32;
            match &rule.selector {
                Selector::Keys(_) => key_rules.push(i),
                Selector::Routes { .. } => route_rules.push(i),
                Selector::Regex(_) => regex_rules.push(i),
                Selector::Detector(d) => match detector_rules.iter_mut().find(|(x, _)| x == d) {
                    Some((_, list)) => list.push(i),
                    None => detector_rules.push((*d, vec![i])),
                },
            }
        }
        // La requête sert aux routes (règles et filtres) et à l'extracteur `http_request`.
        let needs_request = !route_rules.is_empty() || filters.iter().any(CompiledFilter::needs_request) || extractors.http_request;

        Ok(CompiledTemplate {
            id: r.id.clone(),
            name: r.name.clone(),
            version: r.version.clone(),
            chain: r.chain.clone(),
            format,
            format_cfg,
            assemble,
            extractors,
            detector_cfg,
            filters,
            dedup,
            rules,
            allow: compile_allow(id, &r.allowlist)?,
            warnings,
            key_rules,
            route_rules,
            regex_rules,
            detector_rules,
            needs_request,
        })
    }

    /// Règles à clé qui s'appliquent à un chemin (segments en minuscules séparés par `.`).
    pub fn key_rules_for(&self, path: &[u8]) -> Vec<u32> {
        let segs: Vec<&[u8]> = path.split(|b| *b == b'.').collect();
        self.key_rules
            .iter()
            .copied()
            .filter(|&i| match &self.rules[i as usize].selector {
                Selector::Keys(patterns) => patterns.iter().any(|p| p.matches(&segs)),
                _ => false,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;
    use crate::template::library::Library;

    fn key(pattern: &str, path: &str) -> bool {
        let segs: Vec<&[u8]> = path.as_bytes().split(|b| *b == b'.').collect();
        KeyPattern::parse(pattern).unwrap().matches(&segs)
    }

    #[test]
    fn key_patterns() {
        assert!(key("customername", "billingaddress.customername"));
        assert!(key("CustomerName", "customername"));
        assert!(key("cookie.*", "meta.cookie.etam_admin-auth"));
        assert!(!key("cookie.*", "meta.cookie"));
        assert!(key("cookie", "meta.cookie.etam_admin-auth"));
        assert!(key("*address", "shipping_address.country_code"));
        assert!(key("addressline*", "billingaddress.addressline1"));
        assert!(key("products.id", "products.id"));
        assert!(!key("products.id", "products.quantity"));
        assert!(key("state.**.path", "state.a.b.path"));
        assert!(key("$.meta.authorization", "meta.authorization"));
        assert!(!key("$.authorization", "meta.authorization"));
        assert!(!key("city", "cityname"));
    }

    #[cfg(logano_templates)]
    #[test]
    fn builtin_templates_compile() {
        let lib = Library::builtin();
        for id in ["kbrw/common", "kbrw/elixir", "etam/gateway", "kbrw/haproxy", "kbrw/riak-console"] {
            let t = lib.compile(id).unwrap_or_else(|e| panic!("{id} : {e}"));
            assert!(!t.rules.is_empty());
        }
        let t = lib.compile("etam/gateway").unwrap();
        assert_eq!(t.format, FormatKind::ElixirSyslog);
        // La règle des cookies autorise celle des emails à la percer.
        let cookies = t.rules.iter().find(|r| r.id == "kbrw/common:cookies").unwrap();
        let emails = t.rules.iter().position(|r| r.id == "kbrw/common:emails").unwrap();
        assert_eq!(cookies.keep_inner, vec![emails as u32]);
        assert!(t.key_rules_for(b"billingaddress.zipcode").len() >= 2);
        // La gateway réactive la déduplication héritée de kbrw/elixir.
        let dedup = t.dedup.as_ref().expect("dédup active");
        assert!(dedup.ignore_timestamp && dedup.ignore_pid && dedup.ignore_reference);
        assert!(lib.compile("kbrw/elixir").unwrap().dedup.is_none());
    }

    #[test]
    fn invalid_rules_are_rejected_with_context() {
        let base = "[template]\nid='t/x'\nname='x'\nversion='1.0.0'\nschema_version=1\nformat='plain'\n";
        let check = |body: &str, needle: &str| {
            let mut lib = Library::default();
            lib.add_str(&format!("{base}{body}")).unwrap();
            let e = lib.compile("t/x").unwrap_err().to_string();
            assert!(e.contains(needle), "{e}");
        };
        check("[[rules]]\nid='a'\nkeys=['x']\ndetector='email'\nstrategy='redact'\n", "exactement un sélecteur");
        check("[[rules]]\nid='a'\nstrategy='redact'\n", "exactement un sélecteur");
        check("[[rules]]\nid='a'\nkeys=['x']\n", "strategy manquante");
        check("[[rules]]\nid='a'\nkeys=['x']\nstrategy='pseudonymize'\n", "token manquant");
        check("[[rules]]\nid='a'\nkeys=['x']\nstrategy='pseudonymize'\ntoken='bad token'\n", "attendu [A-Z0-9_]+");
        check("[[rules]]\nid='a'\nregex='abc'\nstrategy='redact'\n", "groupe nommé");
        check("[[rules]]\nid='a'\nregex='(?P<v>a'\nstrategy='redact'\n", "regex invalide");
        check("[[rules]]\nid='a'\ndetector='telepathy'\nstrategy='redact'\n", "détecteur inconnu");
        check("[[rules]]\nid='a'\nkeys=['x']\nstrategy='pseudonymize'\ntoken='T'\nkeep_inner=['a']\n", "keep_inner");
        check("[[rules]]\nid='a'\nroute='/api/ping'\nstrategy='redact'\n", "aucun segment");
        check("[[filters]]\nid='f'\n", "aucune condition");
        check("[allowlist]\ncidrs=['not-an-ip/8']\n", "plage invalide");
    }

    fn compile_with(format: &str, body: &str) -> Result<CompiledTemplate> {
        let mut lib = Library::default();
        lib.add_str(&format!("[template]\nid='t/x'\nname='x'\nversion='1.0.0'\nschema_version=1\nformat='{format}'\n{body}")).unwrap();
        lib.compile("t/x")
    }

    #[test]
    fn where_fields_are_checked_against_the_format() {
        let err = |format: &str, body: &str| compile_with(format, body).unwrap_err().to_string();
        let ok = "[[filters]]\nid='f'\nwhere={ status=[400, '404'], request=['<BADREQ>'], server=['<NOSRV>'] }\n";
        let t = compile_with("haproxy_syslog", ok).unwrap();
        assert_eq!(t.filters.len(), 1);
        assert!(t.warnings.is_empty());
        // `where` seul suffit comme condition ; il ne demande pas la requête.
        assert!(!t.filters[0].needs_request());

        let e = err("haproxy_syslog", "[[filters]]\nid='f'\nwhere={ statut=[404] }\n");
        assert!(e.contains("filtre « t/x:f »") && e.contains("champ « statut » inconnu du format haproxy_syslog") && e.contains("status"), "{e}");
        for format in ["elixir_syslog", "lager_syslog", "plain"] {
            let e = err(format, "[[filters]]\nid='f'\nroutes=['/x']\nwhere={ status=[404] }\n");
            assert!(e.contains("champ « status » inconnu") && e.contains(&format!("le format {format} n'expose aucun champ")), "{e}");
        }
        let e = err("haproxy_syslog", "[[filters]]\nid='f'\nwhere={ status=[] }\n");
        assert!(e.contains("where.status : liste vide"), "{e}");
        let e = err("haproxy_syslog", "[[filters]]\nid='f'\nwhere={ status=[4.5] }\n");
        assert!(e.contains("where.status") && e.contains("attendu un entier ou une chaîne"), "{e}");
        let e = err("haproxy_syslog", "[[filters]]\nid='f'\nwhere={ }\n");
        assert!(e.contains("aucune condition"), "{e}");
    }

    #[cfg(logano_templates)]
    #[test]
    fn extractors_follow_the_template() {
        // Sans liste : ceux qui ne dépendent pas du format, plus celui du format.
        let t = compile_with("haproxy_syslog", "").unwrap();
        assert!(t.extractors.haproxy && t.extractors.http_request && !t.extractors.riak_key && t.needs_request);
        let t = compile_with("lager_syslog", "").unwrap();
        assert!(t.extractors.riak_key && !t.extractors.haproxy);
        let t = compile_with("elixir_syslog", "").unwrap();
        assert!(!t.extractors.haproxy && !t.extractors.riak_key && t.extractors.http_request && t.extractors.json);
        // Avec une liste : elle seule.
        let t = compile_with("elixir_syslog", "[extractors]\nenabled=['json', 'riak_key']\n").unwrap();
        assert!(t.extractors.json && t.extractors.riak_key && !t.extractors.http_request && !t.extractors.elixir_term && !t.needs_request);
        assert!(compile_with("plain", "[extractors]\nenabled=['telepathy']\n").unwrap_err().to_string().contains("extracteur inconnu"));

        let lib = Library::builtin();
        let t = lib.compile("kbrw/haproxy").unwrap();
        let x = t.extractors;
        assert!(x.haproxy && x.http_request && !x.json && !x.elixir_term && !x.plug_metadata && !x.cookie && !x.riak_key);
        assert!(t.format_cfg.compact_header);
        assert_eq!(t.format, FormatKind::HaproxySyslog);
        // Les filtres désactivés (tls-handshake-errors, bad-requests) ne sont pas compilés.
        assert_eq!(t.filters.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["kbrw/haproxy:ping", "kbrw/haproxy:system-info", "kbrw/haproxy:scanner-noise"]);
        let t = lib.compile("kbrw/riak-console").unwrap();
        let x = t.extractors;
        assert!(x.riak_key && x.elixir_term && !x.json && !x.http_request && !x.haproxy);
        assert!(!t.format_cfg.compact_header);
        for id in ["kbrw/common", "kbrw/elixir", "kbrw/haproxy", "kbrw/riak-console", "etam/gateway", "etam/services"] {
            assert!(lib.compile(id).unwrap().warnings.is_empty(), "{id}");
        }
    }
}

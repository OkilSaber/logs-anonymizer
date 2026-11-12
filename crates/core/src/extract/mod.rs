//! Extracteurs : repèrent les structures dans le texte d'une entrée et produisent des
//! spans de valeur annotés d'un chemin de clé.

pub mod cookie;
pub mod elixir_term;
pub mod haproxy;
pub mod http_request;
pub mod json;
pub mod plug_metadata;
pub mod riak_key;

use crate::format::FormatKind;
use crate::http::Request;
use memchr::{memchr, memchr2, memmem};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ExtractorId {
    PlugMetadata,
    Cookie,
    Json,
    ElixirTerm,
    HttpRequest,
    Haproxy,
    RiakKey,
}

impl ExtractorId {
    pub const ALL: [ExtractorId; 7] = [
        ExtractorId::PlugMetadata,
        ExtractorId::Cookie,
        ExtractorId::Json,
        ExtractorId::ElixirTerm,
        ExtractorId::HttpRequest,
        ExtractorId::Haproxy,
        ExtractorId::RiakKey,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ExtractorId::PlugMetadata => "plug_metadata",
            ExtractorId::Cookie => "cookie",
            ExtractorId::Json => "json",
            ExtractorId::ElixirTerm => "elixir_term",
            ExtractorId::HttpRequest => "http_request",
            ExtractorId::Haproxy => "haproxy",
            ExtractorId::RiakKey => "riak_key",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "plug_metadata" => ExtractorId::PlugMetadata,
            "cookie" => ExtractorId::Cookie,
            "json" => ExtractorId::Json,
            "elixir_term" => ExtractorId::ElixirTerm,
            "http_request" => ExtractorId::HttpRequest,
            "haproxy" => ExtractorId::Haproxy,
            "riak_key" => ExtractorId::RiakKey,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValueKind {
    Str,
    Number,
    Atom,
    Tuple,
    Opaque,
    Raw,
}

/// Une valeur repérée dans le texte de l'entrée.
#[derive(Clone, Copy, Debug)]
pub struct Span {
    /// Contenu de la valeur, guillemets exclus.
    pub start: u32,
    pub end: u32,
    path_start: u32,
    path_end: u32,
    pub extractor: ExtractorId,
    pub kind: ValueKind,
    /// Le remplacement doit être mis entre guillemets (nombre, atome, tuple…).
    pub quote: bool,
    /// Clé + valeur, pour `drop_field`.
    pub field: Option<(u32, u32)>,
}

/// Clé qui porte la valeur dans une paire nom/valeur.
pub(crate) const PAIR_VALUE: &[u8] = b"value";

/// Clé qui porte le nom dans une paire nom/valeur : `%{name: :firstName, value: "Jean"}`.
pub(crate) fn is_pair_name(key: &[u8]) -> bool {
    key.eq_ignore_ascii_case(b"name") || key.eq_ignore_ascii_case(b"key")
}

/// Suivi d'une paire nom/valeur pendant l'analyse d'un conteneur.
#[derive(Default)]
pub(crate) struct Pair {
    name: Option<(u32, u32)>,
    value: Option<(usize, usize)>,
}

impl Pair {
    /// À appeler après chaque clé du conteneur, avec les spans qu'elle vient de produire.
    /// Dès que le nom et la valeur sont connus, le chemin de la valeur est renommé.
    pub(crate) fn note(&mut self, key: &[u8], before: usize, text: &[u8], base: usize, sp: &mut Spans) {
        let after = sp.items.len();
        if is_pair_name(key) {
            // Le nom doit être un scalaire simple : un atome ou une chaîne.
            if after == before + 1 && matches!(sp.items[before].kind, ValueKind::Atom | ValueKind::Str) {
                self.name = Some((sp.items[before].start, sp.items[before].end));
            }
        } else if key.eq_ignore_ascii_case(PAIR_VALUE) {
            self.value = Some((before, after));
        } else {
            return;
        }
        if let (Some((ns, ne)), Some((vs, ve))) = (self.name, self.value) {
            sp.rename_value_segment(vs..ve, base, &text[ns as usize..ne as usize]);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExtractorSet {
    pub plug_metadata: bool,
    pub cookie: bool,
    pub json: bool,
    pub elixir_term: bool,
    pub http_request: bool,
    /// Propre au format `haproxy_syslog`.
    pub haproxy: bool,
    /// Propre au format `lager_syslog`.
    pub riak_key: bool,
    pub max_depth: usize,
}

impl Default for ExtractorSet {
    /// Les extracteurs indépendants du format.
    fn default() -> Self {
        ExtractorSet {
            plug_metadata: true,
            cookie: true,
            json: true,
            elixir_term: true,
            http_request: true,
            haproxy: false,
            riak_key: false,
            max_depth: 64,
        }
    }
}

impl ExtractorSet {
    /// Extracteurs d'un template qui n'en liste aucun : ceux par défaut, plus celui du format.
    pub fn for_format(format: FormatKind) -> Self {
        ExtractorSet {
            haproxy: format == FormatKind::HaproxySyslog,
            riak_key: format == FormatKind::LagerSyslog,
            ..ExtractorSet::default()
        }
    }

    pub fn set(&mut self, id: ExtractorId, enabled: bool) {
        match id {
            ExtractorId::PlugMetadata => self.plug_metadata = enabled,
            ExtractorId::Cookie => self.cookie = enabled,
            ExtractorId::Json => self.json = enabled,
            ExtractorId::ElixirTerm => self.elixir_term = enabled,
            ExtractorId::HttpRequest => self.http_request = enabled,
            ExtractorId::Haproxy => self.haproxy = enabled,
            ExtractorId::RiakKey => self.riak_key = enabled,
        }
    }
}

/// Spans d'une entrée, avec l'arène des chemins et les régions déjà traitées.
#[derive(Default)]
pub struct Spans {
    pub items: Vec<Span>,
    paths: Vec<u8>,
    claimed: Vec<(u32, u32)>,
    /// Chemin courant pendant l'extraction, segments en minuscules séparés par `.`.
    cur: Vec<u8>,
}

impl Spans {
    pub fn clear(&mut self) {
        self.items.clear();
        self.paths.clear();
        self.claimed.clear();
        self.cur.clear();
    }

    /// Empile un segment de chemin ; rend la marque à passer à [`Spans::pop_seg`].
    pub fn push_seg(&mut self, seg: &[u8]) -> usize {
        let mark = self.cur.len();
        if !self.cur.is_empty() {
            self.cur.push(b'.');
        }
        for &b in seg {
            self.cur.push(if b == b'.' { b'_' } else { b.to_ascii_lowercase() });
        }
        mark
    }

    pub fn pop_seg(&mut self, mark: usize) {
        self.cur.truncate(mark);
    }

    fn set_path(&mut self, path: &[u8]) {
        self.cur.clear();
        self.cur.extend_from_slice(path);
    }

    /// Ajoute une valeur feuille au chemin courant. Ignorée si vide ou sans chemin.
    pub fn leaf(&mut self, start: usize, end: usize, extractor: ExtractorId, kind: ValueKind, quote: bool) {
        if start >= end || self.cur.is_empty() {
            return;
        }
        let path_start = self.paths.len() as u32;
        self.paths.extend_from_slice(&self.cur);
        self.items.push(Span {
            start: start as u32,
            end: end as u32,
            path_start,
            path_end: self.paths.len() as u32,
            extractor,
            kind,
            quote,
            field: None,
        });
    }

    /// Longueur du chemin courant, en octets.
    pub(crate) fn cur_len(&self) -> usize {
        self.cur.len()
    }

    /// Paire `name`/`value` : dans les spans `range`, le segment `value` situé juste après
    /// le chemin du conteneur (`base` octets) est remplacé par le nom porté par `name`.
    /// `%{name: :firstName, value: "Jean"}` sous `properties` donne `properties.firstname`.
    pub(crate) fn rename_value_segment(&mut self, range: std::ops::Range<usize>, base: usize, name: &[u8]) {
        let name = name.strip_prefix(b":").unwrap_or(name);
        if name.is_empty() || name.len() > 64 {
            return;
        }
        let seg = base + usize::from(base > 0);
        for idx in range {
            let s = self.items[idx];
            let old = self.paths[s.path_start as usize..s.path_end as usize].to_vec();
            let after = seg + PAIR_VALUE.len();
            let is_value = old.len() >= after && &old[seg..after] == PAIR_VALUE && (old.len() == after || old[after] == b'.');
            if !is_value {
                continue;
            }
            let start = self.paths.len() as u32;
            self.paths.extend_from_slice(&old[..seg]);
            self.paths.extend(name.iter().map(|b| if *b == b'.' { b'_' } else { b.to_ascii_lowercase() }));
            self.paths.extend_from_slice(&old[after..]);
            self.items[idx].path_start = start;
            self.items[idx].path_end = self.paths.len() as u32;
        }
    }

    pub fn path(&self, s: &Span) -> &[u8] {
        &self.paths[s.path_start as usize..s.path_end as usize]
    }

    pub fn claim(&mut self, start: usize, end: usize) {
        if end > start {
            self.claimed.push((start as u32, end as u32));
        }
    }

    pub fn is_claimed(&self, pos: usize) -> bool {
        let p = pos as u32;
        self.claimed.iter().any(|&(s, e)| s <= p && p < e)
    }
}

/// Lance les extracteurs activés dont le déclencheur est présent. `req` est la requête
/// HTTP de l'entrée, telle que la rend [`crate::format::Format::request`].
pub fn run(text: &[u8], header_len: usize, req: Option<&Request>, set: &ExtractorSet, sp: &mut Spans) {
    sp.clear();
    if set.haproxy {
        haproxy::scan(text, header_len, sp);
    }
    if set.http_request {
        if let Some(req) = req.filter(|r| r.query.is_some()) {
            http_request::scan(text, req, sp);
        }
    }
    if set.plug_metadata && header_len < text.len() && memchr(b'\t', &text[header_len..]).is_some() {
        plug_metadata::scan(text, header_len, set, sp);
    }
    if set.elixir_term && memchr2(b'%', b'[', text).is_some() {
        elixir_term::scan(text, sp, set.max_depth);
    }
    if set.json && memchr(b'{', text).is_some() {
        json::scan(text, sp, set.max_depth);
    }
    if set.riak_key && memmem::find(text, b"\">>/<<\"").is_some() {
        riak_key::scan(text, sp);
    }
    if set.cookie {
        cascade_cookies(text, sp);
    }
}

/// `"cookie" => "a=b; c=d"` dans un terme ou un JSON : la valeur est redécoupée par cookie.
fn cascade_cookies(text: &[u8], sp: &mut Spans) {
    let n = sp.items.len();
    for idx in 0..n {
        let s = sp.items[idx];
        if s.kind != ValueKind::Str || !matches!(s.extractor, ExtractorId::Json | ExtractorId::ElixirTerm) {
            continue;
        }
        let path = sp.path(&s);
        let last = path.rsplit(|b| *b == b'.').next().unwrap_or(path);
        let set_cookie = last == b"set-cookie";
        if last != b"cookie" && !set_cookie {
            continue;
        }
        let path = path.to_vec();
        sp.set_path(&path);
        let found = cookie::parse(text, s.start as usize, s.end as usize, set_cookie, sp);
        sp.cur.clear();
        if found > 0 {
            // Le parent devient un conteneur : il ne porte plus de valeur.
            sp.items[idx].end = sp.items[idx].start;
        }
    }
}

#[cfg(test)]
pub(crate) fn dump(text: &[u8], sp: &Spans) -> Vec<(String, String)> {
    sp.items
        .iter()
        .filter(|s| s.end > s.start)
        .map(|s| {
            (
                String::from_utf8_lossy(sp.path(s)).into_owned(),
                String::from_utf8_lossy(&text[s.start as usize..s.end as usize]).into_owned(),
            )
        })
        .collect()
}

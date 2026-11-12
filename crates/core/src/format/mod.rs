//! Formats de logs : cadrage d'une ligne physique et classification pour l'assembleur.

pub mod elixir;
pub mod haproxy;
pub mod lager;
pub mod plain;

use crate::entry::{EntryKind, Level};
use crate::error::Result;
use crate::http::{find_request, Request};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatKind {
    ElixirSyslog,
    HaproxySyslog,
    LagerSyslog,
    Plain,
}

impl FormatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FormatKind::ElixirSyslog => "elixir_syslog",
            FormatKind::HaproxySyslog => "haproxy_syslog",
            FormatKind::LagerSyslog => "lager_syslog",
            FormatKind::Plain => "plain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "elixir_syslog" => FormatKind::ElixirSyslog,
            "haproxy_syslog" => FormatKind::HaproxySyslog,
            "lager_syslog" => FormatKind::LagerSyslog,
            "plain" => FormatKind::Plain,
            _ => return None,
        })
    }
}

/// Options d'un format, tirées de `[format.options]` du template.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FormatConfig {
    /// `haproxy_syslog` : le contenu de l'entrée est le payload seul, sans
    /// `<ISO8601> <host> haproxy[<pid>]: ` que syslog répète sur chaque ligne.
    pub compact_header: bool,
}

pub struct Framed<'a> {
    pub source: &'a [u8],
    pub content: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineClass {
    /// Ouvre une entrée (et ferme celle de la même source).
    Start { level: Option<Level> },
    /// Entrée à elle seule ; ferme celle de la même source.
    Standalone(EntryKind),
    /// Ligne vide ou ne contenant que des codes ANSI.
    Separator,
    Continuation,
}

pub trait Format: Send + Sync {
    fn kind(&self) -> FormatKind;
    /// Ligne physique (sans `\n` ni `\r`) → (source, contenu).
    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a>;
    /// Ne lit que les premiers octets du contenu (ANSI déjà retiré).
    fn classify(&self, content: &[u8]) -> LineClass;
    /// Début du message dans la ligne d'en-tête (après horodatage et niveau).
    fn message_start(&self, header: &[u8]) -> usize;

    /// Requête HTTP d'une entrée, pour les routes et l'extracteur `http_request`.
    /// `header` est la première ligne de l'entrée ; les positions rendues s'y rapportent
    /// (donc aussi au texte de l'entrée). Par défaut : `MÉTHODE /chemin` cherché dans le message.
    fn request(&self, header: &[u8]) -> Option<Request> {
        find_request(header, self.message_start(header))
    }

    /// Noms des champs d'en-tête que [`Format::field`] sait lire (conditions `where` des filtres).
    fn field_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// Valeur d'un champ d'en-tête, par son nom ; `None` si le format ne l'expose pas ou
    /// si cette entrée ne le porte pas.
    fn field<'a>(&self, _header: &'a [u8], _name: &str) -> Option<&'a [u8]> {
        None
    }
}

/// Format avec ses options par défaut.
pub fn make_format(kind: FormatKind) -> Result<Arc<dyn Format>> {
    make_format_with(kind, FormatConfig::default())
}

pub fn make_format_with(kind: FormatKind, cfg: FormatConfig) -> Result<Arc<dyn Format>> {
    Ok(match kind {
        FormatKind::ElixirSyslog => Arc::new(elixir::ElixirSyslog),
        FormatKind::HaproxySyslog => Arc::new(haproxy::HaproxySyslog { compact_header: cfg.compact_header }),
        FormatKind::LagerSyslog => Arc::new(lager::LagerSyslog),
        FormatKind::Plain => Arc::new(plain::Plain),
    })
}

/// Un host émetteur plausible : `[A-Za-z0-9._-]+`, au moins une lettre, 255 octets au plus.
pub(crate) fn hostname_like(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && s.iter().any(|b| b.is_ascii_alphabetic())
}

/// Coupe au premier double espace si ce qui précède ressemble à un host.
pub(crate) fn frame_syslog(line: &[u8]) -> Framed<'_> {
    if let Some(i) = memchr::memmem::find(line, b"  ") {
        if hostname_like(&line[..i]) {
            return Framed { source: &line[..i], content: &line[i + 2..] };
        }
    }
    // Séparateur dont les espaces finaux ont été perdus : la ligne se réduit au host.
    let bare = line.trim_ascii_end();
    if hostname_like(bare) && bare.contains(&b'.') {
        return Framed { source: bare, content: b"" };
    }
    Framed { source: b"", content: line }
}

use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EntryKind {
    /// Entrée Logger : `HH:MM:SS.mmm [level] …` et ses continuations.
    Logger,
    /// `===== ALIVE …` ou `=====` seul.
    Alive,
    /// `===== LOGGING STARTED …`
    LoggingStarted,
    /// Métrique statsd : `nom:1|c`.
    Statsd,
    /// `[2026-11-09 00:51:59.786109Z UTC] …` (IO.puts).
    IoTimestamped,
    /// `message repeated N times: [ … ]` (rsyslog).
    Repeated,
    /// Continuation sans entrée ouverte pour sa source.
    Orphan,
    /// Autre ligne hors Logger.
    Other,
    /// Format `plain` : une ligne = une entrée.
    Plain,
    /// HAProxy : requête HTTP (`… tls[…] t[…] c[…] sz[…] … hds[…] req["…"]`).
    Http,
    /// HAProxy : connexion TCP (sftp).
    Tcp,
    /// HAProxy : échec de la poignée de main TLS (`<frontend>/1: SSL handshake failure`).
    TlsError,
}

impl EntryKind {
    pub const ALL: [EntryKind; 12] = [
        EntryKind::Logger,
        EntryKind::Alive,
        EntryKind::LoggingStarted,
        EntryKind::Statsd,
        EntryKind::IoTimestamped,
        EntryKind::Repeated,
        EntryKind::Orphan,
        EntryKind::Other,
        EntryKind::Plain,
        EntryKind::Http,
        EntryKind::Tcp,
        EntryKind::TlsError,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Logger => "logger",
            EntryKind::Alive => "alive",
            EntryKind::LoggingStarted => "logging_started",
            EntryKind::Statsd => "statsd",
            EntryKind::IoTimestamped => "io_timestamped",
            EntryKind::Repeated => "repeated",
            EntryKind::Orphan => "orphan",
            EntryKind::Other => "other",
            EntryKind::Plain => "plain",
            EntryKind::Http => "http",
            EntryKind::Tcp => "tcp",
            EntryKind::TlsError => "tls_error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Level {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Notice => "notice",
            Level::Warning => "warning",
            Level::Error => "error",
            Level::Critical => "critical",
            Level::Alert => "alert",
            Level::Emergency => "emergency",
        }
    }

    pub fn parse(s: &[u8]) -> Option<Self> {
        Some(match s {
            b"debug" => Level::Debug,
            b"info" => Level::Info,
            b"notice" => Level::Notice,
            b"warning" | b"warn" => Level::Warning,
            b"error" => Level::Error,
            b"critical" => Level::Critical,
            b"alert" => Level::Alert,
            b"emergency" => Level::Emergency,
            _ => return None,
        })
    }
}

/// Une entrée de log : une ou plusieurs lignes d'une même source.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Host émetteur (vide pour le format `plain` ou une ligne sans préfixe).
    pub source: Arc<str>,
    /// Numéro (base 1) de la première ligne physique.
    pub line_no: u64,
    pub kind: EntryKind,
    pub level: Option<Level>,
    /// Lignes jointes par `\n`, sans préfixe host, sans `\r`, sans ANSI si l'option est active.
    pub text: Vec<u8>,
    pub lines: u32,
}

impl Entry {
    /// Longueur de la première ligne.
    pub fn header_len(&self) -> usize {
        memchr::memchr(b'\n', &self.text).unwrap_or(self.text.len())
    }

    pub fn header(&self) -> &[u8] {
        &self.text[..self.header_len()]
    }
}

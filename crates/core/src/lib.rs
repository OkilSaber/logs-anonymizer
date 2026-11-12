//! Moteur d'anonymisation de logs.
//!
//! Flux : octets → lignes → cadrage → entrées (une ouverte par source) → filtres
//! → extracteurs → règles + détecteurs → résolution des chevauchements → reconstruction
//! → filet de sécurité → sortie [`safety::Sanitized`].

pub mod ansi;
pub mod assemble;
pub mod detect;
pub mod engine;
pub mod entry;
pub mod error;
pub mod extract;
pub mod format;
pub mod glob;
pub mod http;
pub mod netaddr;
pub mod output;
pub mod overlap;
pub mod pipeline;
pub mod profile;
pub mod pseudonym;
pub mod rules;
pub mod safety;
pub mod stats;
pub mod strategy;
pub mod template;

pub use engine::{Engine, EngineOptions, SafetyAction};
pub use entry::{Entry, EntryKind, Level};
pub use error::CoreError;
pub use pipeline::{run, sandbox, Layout, Progress, RunOptions, SandboxEntry, Segment};
pub use stats::Stats;
pub use template::library::Library;

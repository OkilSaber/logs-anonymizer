//! Statistiques d'un traitement, fusionnables entre lots.

use crate::detect::DetectorId;
use serde::Serialize;

/// Une intervention du filet de sécurité : un trou de couverture du template.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SafetyFinding {
    pub detector: &'static str,
    pub source: String,
    pub line_no: u64,
    /// Extrait de la sortie anonymisée autour du remplacement. Vide en mode `report`,
    /// où la valeur n'a pas été remplacée.
    pub context: String,
    pub replaced: bool,
}

pub const MAX_FINDINGS: usize = 200;

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub entries_in: u64,
    pub entries_out: u64,
    pub dropped: u64,
    pub modified: u64,
    pub lines_in: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Par règle du template compilé : remplacements appliqués.
    pub rule_hits: Vec<u64>,
    /// Par règle : candidats écartés par une autre règle.
    pub shadowed: Vec<u64>,
    pub filter_hits: Vec<u64>,
    /// Par détecteur ([`DetectorId::ALL`]) : interventions du filet de sécurité.
    pub safety_hits: Vec<u64>,
    /// Chevauchements partiels masqués en bloc.
    pub merged: u64,
    /// Entrées identiques à la précédente de la même source, remplacées par un compteur.
    pub deduplicated: u64,
    pub findings: Vec<SafetyFinding>,
    /// Erreur de lecture rencontrée (fichier compressé tronqué…) ; ce qui précède a été traité.
    pub input_error: Option<String>,
}

impl Stats {
    pub fn sized(rules: usize, filters: usize) -> Self {
        Stats {
            rule_hits: vec![0; rules],
            shadowed: vec![0; rules],
            filter_hits: vec![0; filters],
            safety_hits: vec![0; DetectorId::ALL.len()],
            ..Default::default()
        }
    }

    pub fn safety_total(&self) -> u64 {
        self.safety_hits.iter().sum()
    }

    pub fn merge(&mut self, o: Stats) {
        self.entries_in += o.entries_in;
        self.entries_out += o.entries_out;
        self.dropped += o.dropped;
        self.modified += o.modified;
        self.lines_in += o.lines_in;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        self.merged += o.merged;
        self.deduplicated += o.deduplicated;
        for (dst, src) in [
            (&mut self.rule_hits, &o.rule_hits),
            (&mut self.shadowed, &o.shadowed),
            (&mut self.filter_hits, &o.filter_hits),
            (&mut self.safety_hits, &o.safety_hits),
        ] {
            if dst.len() < src.len() {
                dst.resize(src.len(), 0);
            }
            for (d, s) in dst.iter_mut().zip(src) {
                *d += s;
            }
        }
        let room = MAX_FINDINGS.saturating_sub(self.findings.len());
        self.findings.extend(o.findings.into_iter().take(room));
        if self.input_error.is_none() {
            self.input_error = o.input_error;
        }
    }
}

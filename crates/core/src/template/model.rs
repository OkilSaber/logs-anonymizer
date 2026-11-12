//! Forme d'un fichier de template, telle qu'écrite en TOML.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFile {
    pub template: Meta,
    #[serde(default)]
    pub format: FormatSection,
    #[serde(default)]
    pub extractors: ExtractorsSection,
    #[serde(default)]
    pub detectors: BTreeMap<String, toml::Table>,
    #[serde(default)]
    pub filters: Vec<FilterDef>,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub allowlist: Allowlist,
    #[serde(default)]
    pub tests: Vec<TestDef>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub id: String,
    pub name: String,
    pub version: String,
    pub schema_version: u32,
    pub author: Option<String>,
    pub description: Option<String>,
    pub log_kind: Option<String>,
    pub format: Option<String>,
    #[serde(default, rename = "abstract")]
    pub is_abstract: bool,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub suggested_apps: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatSection {
    #[serde(default)]
    pub options: FormatOptions,
}

/// Taille en octets : entier ou chaîne (`"1MiB"`, `"256KiB"`, `"4MB"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn parse(s: &str) -> Option<ByteSize> {
        let s = s.trim();
        let split = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
        let n: f64 = s[..split].parse().ok()?;
        let mult: u64 = match s[split..].trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" => 1_000,
            "kib" => 1 << 10,
            "m" | "mb" => 1_000_000,
            "mib" => 1 << 20,
            "g" | "gb" => 1_000_000_000,
            "gib" => 1 << 30,
            _ => return None,
        };
        Some(ByteSize((n * mult as f64) as u64))
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u64),
            Str(String),
        }
        match Repr::deserialize(d)? {
            Repr::Int(n) => Ok(ByteSize(n)),
            Repr::Str(s) => ByteSize::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("taille invalide : « {s} »"))),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatOptions {
    pub strip_ansi: Option<bool>,
    pub max_entry_lines: Option<u32>,
    pub max_entry_bytes: Option<ByteSize>,
    pub reorder_window: Option<u32>,
    pub metadata_prefix: Option<bool>,
    pub compact_header: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractorsSection {
    pub enabled: Option<Vec<String>>,
    #[serde(default)]
    pub options: BTreeMap<String, toml::Table>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterDef {
    pub id: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    pub routes: Option<Vec<String>>,
    pub header: Option<String>,
    pub kinds: Option<Vec<String>>,
    pub levels: Option<Vec<String>>,
    #[serde(rename = "where")]
    pub where_: Option<BTreeMap<String, Vec<toml::Value>>>,
    pub ignore: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
    pub keys: Option<Vec<String>>,
    pub route: Option<String>,
    pub routes: Option<Vec<String>>,
    pub regex: Option<String>,
    pub detector: Option<String>,
    pub extractors: Option<Vec<String>>,
    pub kinds: Option<Vec<String>>,
    pub levels: Option<Vec<String>>,
    pub targets: Option<Vec<String>>,
    pub strategy: Option<String>,
    pub token: Option<String>,
    pub label: Option<String>,
    pub mask: Option<String>,
    pub normalize: Option<String>,
    pub preserve: Option<String>,
    pub keep_inner: Option<Vec<String>>,
}

macro_rules! patch_fields {
    ($dst:expr, $src:expr, $($f:ident),+ $(,)?) => {
        $( if $src.$f.is_some() { $dst.$f = $src.$f.clone(); } )+
    };
}

impl RuleDef {
    /// Surcharge : seuls les champs précisés par `other` remplacent ceux de `self`.
    pub fn patch(&mut self, other: &RuleDef) {
        patch_fields!(
            self, other, description, enabled, priority, keys, route, routes, regex, detector, extractors, kinds,
            levels, targets, strategy, token, label, mask, normalize, preserve, keep_inner
        );
    }
}

impl FilterDef {
    pub fn patch(&mut self, other: &FilterDef) {
        patch_fields!(self, other, description, enabled, action, routes, header, kinds, levels, where_, ignore);
    }
}

impl FormatOptions {
    pub fn patch(&mut self, other: &FormatOptions) {
        patch_fields!(self, other, strip_ansi, max_entry_lines, max_entry_bytes, reorder_window, metadata_prefix, compact_header);
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// Noms d'hôtes uniquement, jamais les emails.
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

impl Allowlist {
    pub fn union(&mut self, other: &Allowlist) {
        for (dst, src) in [
            (&mut self.domains, &other.domains),
            (&mut self.cidrs, &other.cidrs),
            (&mut self.emails, &other.emails),
            (&mut self.values, &other.values),
        ] {
            for v in src {
                if !dst.contains(v) {
                    dst.push(v.clone());
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.cidrs.is_empty() && self.emails.is_empty() && self.values.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestDef {
    pub name: String,
    pub input: String,
    pub expected: Option<String>,
    #[serde(default)]
    pub expect_contains: Vec<String>,
    #[serde(default)]
    pub expect_not_contains: Vec<String>,
    pub expect_dropped: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_sizes() {
        assert_eq!(ByteSize::parse("1MiB"), Some(ByteSize(1 << 20)));
        assert_eq!(ByteSize::parse("256KiB"), Some(ByteSize(256 << 10)));
        assert_eq!(ByteSize::parse("4 MB"), Some(ByteSize(4_000_000)));
        assert_eq!(ByteSize::parse("12"), Some(ByteSize(12)));
        assert_eq!(ByteSize::parse("1 parsec"), None);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = "[template]\nid='a/b'\nname='x'\nversion='1.0.0'\nschema_version=1\n[[rules]]\nid='r'\nexec='rm -rf /'\n";
        assert!(toml::from_str::<TemplateFile>(toml).is_err());
    }
}

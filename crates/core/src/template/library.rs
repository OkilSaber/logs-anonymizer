//! Bibliothèque locale de templates et résolution de l'héritage.

use super::model::{Allowlist, FilterDef, FormatOptions, RuleDef, TemplateFile};
use super::SCHEMA_VERSION;
use crate::error::{CoreError, Result};
use crate::rules::CompiledTemplate;
use std::collections::BTreeMap;
use std::path::Path;

/// Templates embarqués à la compilation : ceux du dossier `templates/` du dépôt, avec la
/// fonctionnalité `embedded-templates` (voir `build.rs`). Vide sinon : l'app distribuée n'en
/// contient aucun, ils s'importent depuis l'interface.
const BUILTIN: &[&str] = include!(concat!(env!("OUT_DIR"), "/builtin_templates.rs"));

/// Socle générique, toujours embarqué : il prend tout fichier qui n'a pas de template plus
/// précis, pour qu'une app sans aucun template importé sache quand même anonymiser ce qui
/// se reconnaît à sa forme, et profiler des logs.
const BASE: [&str; 4] = [
    include_str!("../../templates/base/common.toml"),
    include_str!("../../templates/base/elixir.toml"),
    include_str!("../../templates/base/haproxy.toml"),
    include_str!("../../templates/base/riak-console.toml"),
];

/// Espace de noms du socle générique. Ses templates passent après tous les autres.
pub const BASE_NAMESPACE: &str = "base/";

/// Un template dont l'héritage est résolu : règles et filtres portent un id qualifié
/// `<template d'origine>:<id>`.
#[derive(Clone, Debug, Default)]
pub struct Resolved {
    pub id: String,
    pub name: String,
    pub version: String,
    pub format: Option<String>,
    pub options: FormatOptions,
    pub extractors: Option<Vec<String>>,
    pub extractor_options: BTreeMap<String, toml::Table>,
    pub detectors: BTreeMap<String, toml::Table>,
    pub rules: Vec<(String, RuleDef)>,
    pub filters: Vec<(String, FilterDef)>,
    pub allowlist: Allowlist,
    /// Chaîne d'héritage, du plus ancien parent au template lui-même : (id, version).
    pub chain: Vec<(String, String)>,
}

#[derive(Clone, Default)]
pub struct Library {
    files: BTreeMap<String, TemplateFile>,
    sources: BTreeMap<String, String>,
    builtin: Vec<String>,
}

impl Library {
    /// Bibliothèque contenant les templates embarqués : le socle générique, toujours, et
    /// ceux du dossier `templates/` du dépôt quand ils sont compilés avec.
    pub fn builtin() -> Self {
        let mut lib = Library::default();
        for src in BASE.iter().chain(BUILTIN.iter()).copied() {
            let id = lib.add_str(src).expect("les templates fournis sont valides");
            lib.builtin.push(id);
        }
        lib
    }

    /// Ajoute (ou remplace) un template depuis son texte TOML. Rend son id.
    pub fn add_str(&mut self, src: &str) -> Result<String> {
        let file: TemplateFile = toml::from_str(src).map_err(|e| CoreError::Toml(e.to_string()))?;
        let id = file.template.id.clone();
        // Chaque segment est non vide : l'id sert de chemin relatif dans le dossier des templates.
        if id.split('/').any(str::is_empty) || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_')) {
            return Err(CoreError::template(&id, "id invalide : attendu <espace>/<nom> en [A-Za-z0-9_-]"));
        }
        if file.template.schema_version != SCHEMA_VERSION {
            return Err(CoreError::template(
                &id,
                format!("schema_version {} non pris en charge (attendu {SCHEMA_VERSION})", file.template.schema_version),
            ));
        }
        semver::Version::parse(&file.template.version)
            .map_err(|e| CoreError::template(&id, format!("version « {} » invalide : {e}", file.template.version)))?;
        self.sources.insert(id.clone(), src.to_string());
        self.files.insert(id.clone(), file);
        Ok(id)
    }

    /// Charge tous les `.toml` d'un dossier, récursivement. Les fichiers invalides sont
    /// rendus avec leur erreur, sans interrompre le chargement.
    pub fn load_dir(&mut self, dir: &Path) -> Vec<(std::path::PathBuf, CoreError)> {
        let mut errors = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|e| e == "toml") {
                    match std::fs::read_to_string(&p) {
                        Ok(src) => {
                            if let Err(e) = self.add_str(&src) {
                                errors.push((p, e));
                            }
                        }
                        Err(e) => errors.push((p, e.into())),
                    }
                }
            }
        }
        errors
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    pub fn get(&self, id: &str) -> Option<&TemplateFile> {
        self.files.get(id)
    }

    pub fn source(&self, id: &str) -> Option<&str> {
        self.sources.get(id).map(String::as_str)
    }

    pub fn is_builtin(&self, id: &str) -> bool {
        self.builtin.iter().any(|b| b == id)
    }

    pub fn resolve(&self, id: &str) -> Result<Resolved> {
        self.resolve_inner(id, &mut Vec::new())
    }

    /// Résout l'héritage puis compile le template pour le moteur.
    pub fn compile(&self, id: &str) -> Result<CompiledTemplate> {
        CompiledTemplate::compile(&self.resolve(id)?)
    }

    fn resolve_inner(&self, id: &str, stack: &mut Vec<String>) -> Result<Resolved> {
        if stack.iter().any(|s| s == id) {
            return Err(CoreError::InheritanceCycle(id.to_string()));
        }
        let file = self.files.get(id).ok_or_else(|| CoreError::TemplateNotFound(id.to_string()))?;
        stack.push(id.to_string());
        let mut r = Resolved::default();
        for parent_ref in &file.template.extends {
            let (pid, req) = match parent_ref.split_once('@') {
                Some((p, q)) => (p.trim(), Some(q.trim())),
                None => (parent_ref.trim(), None),
            };
            let missing = || CoreError::ParentMissing { id: id.to_string(), parent: parent_ref.clone() };
            let parent = self.files.get(pid).ok_or_else(missing)?;
            if let Some(req) = req {
                let req = semver::VersionReq::parse(req)
                    .map_err(|e| CoreError::template(id, format!("contrainte « {parent_ref} » invalide : {e}")))?;
                let version = semver::Version::parse(&parent.template.version).map_err(|_| missing())?;
                if !req.matches(&version) {
                    return Err(missing());
                }
            }
            let p = self.resolve_inner(pid, stack)?;
            merge_parent(&mut r, p, id)?;
        }
        stack.pop();

        let meta = &file.template;
        if let Some(fmt) = &meta.format {
            if r.format.as_ref().is_some_and(|pf| pf != fmt) {
                return Err(CoreError::template(id, format!("format « {fmt} » différent de celui du parent")));
            }
            r.format = Some(fmt.clone());
        }
        if r.format.is_none() && !meta.is_abstract {
            return Err(CoreError::template(id, "format manquant (ou template à déclarer abstract = true)"));
        }
        r.options.patch(&file.format.options);
        if file.extractors.enabled.is_some() {
            r.extractors = file.extractors.enabled.clone();
        }
        r.extractor_options.extend(file.extractors.options.clone());
        r.detectors.extend(file.detectors.clone());
        r.allowlist.union(&file.allowlist);

        for def in &file.rules {
            if def.id.contains(':') {
                let slot = r
                    .rules
                    .iter_mut()
                    .find(|(qid, _)| *qid == def.id)
                    .ok_or_else(|| CoreError::template(id, format!("surcharge d'une règle inconnue : « {} »", def.id)))?;
                slot.1.patch(def);
            } else {
                let qid = format!("{id}:{}", def.id);
                if r.rules.iter().any(|(q, _)| *q == qid) {
                    return Err(CoreError::template(id, format!("règle « {} » définie deux fois", def.id)));
                }
                let mut def = def.clone();
                // Les références locales de keep_inner deviennent des ids qualifiés.
                if let Some(list) = &mut def.keep_inner {
                    for k in list.iter_mut().filter(|k| !k.contains(':')) {
                        *k = format!("{id}:{k}");
                    }
                }
                r.rules.push((qid, def));
            }
        }
        for def in &file.filters {
            if def.id.contains(':') {
                let slot = r
                    .filters
                    .iter_mut()
                    .find(|(qid, _)| *qid == def.id)
                    .ok_or_else(|| CoreError::template(id, format!("surcharge d'un filtre inconnu : « {} »", def.id)))?;
                slot.1.patch(def);
            } else {
                let qid = format!("{id}:{}", def.id);
                if r.filters.iter().any(|(q, _)| *q == qid) {
                    return Err(CoreError::template(id, format!("filtre « {} » défini deux fois", def.id)));
                }
                r.filters.push((qid, def.clone()));
            }
        }

        r.id = meta.id.clone();
        r.name = meta.name.clone();
        r.version = meta.version.clone();
        r.chain.push((meta.id.clone(), meta.version.clone()));
        Ok(r)
    }
}

fn merge_parent(r: &mut Resolved, p: Resolved, child: &str) -> Result<()> {
    if let Some(pf) = p.format {
        if r.format.as_ref().is_some_and(|f| *f != pf) {
            return Err(CoreError::template(child, "les parents n'ont pas le même format"));
        }
        r.format = Some(pf);
    }
    r.options.patch(&p.options);
    if p.extractors.is_some() {
        r.extractors = p.extractors;
    }
    r.extractor_options.extend(p.extractor_options);
    r.detectors.extend(p.detectors);
    r.allowlist.union(&p.allowlist);
    // Héritage en losange : une règle déjà apportée par un autre parent n'est pas doublée.
    for (qid, def) in p.rules {
        if !r.rules.iter().any(|(q, _)| *q == qid) {
            r.rules.push((qid, def));
        }
    }
    for (qid, def) in p.filters {
        if !r.filters.iter().any(|(q, _)| *q == qid) {
            r.filters.push((qid, def));
        }
    }
    for link in p.chain {
        if !r.chain.contains(&link) {
            r.chain.push(link);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;

    const BASE: &str = "[template]\nid='t/base'\nname='b'\nversion='1.2.0'\nschema_version=1\nformat='plain'\n[[rules]]\nid='emails'\ndetector='email'\nstrategy='pseudonymize'\ntoken='EMAIL'\n[[rules]]\nid='zip'\nkeys=['zip']\nstrategy='pseudonymize'\ntoken='ZIP'\n";

    fn child(extends: &str, body: &str) -> String {
        format!("[template]\nid='t/child'\nname='c'\nversion='1.0.0'\nschema_version=1\nextends=['{extends}']\n{body}")
    }

    #[cfg(logano_templates)]
    #[test]
    fn builtin_templates_resolve() {
        let lib = Library::builtin();
        let r = lib.resolve("etam/gateway").unwrap();
        assert_eq!(r.format.as_deref(), Some("elixir_syslog"));
        assert_eq!(
            r.chain.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>(),
            vec!["kbrw/common", "kbrw/elixir", "etam/gateway"]
        );
        // Surcharge d'une règle du grand-parent : la stratégie change, les clés restent.
        let (_, zip) = r.rules.iter().find(|(q, _)| q == "kbrw/common:postal-codes").unwrap();
        assert_eq!(zip.strategy.as_deref(), Some("mask_partial"));
        assert!(zip.keys.as_ref().unwrap().contains(&"zipcode*".to_string()));
        // Filtre hérité réactivé.
        let (_, dedup) = r.filters.iter().find(|(q, _)| q == "kbrw/elixir:dedup").unwrap();
        assert_eq!(dedup.enabled, Some(true));
        // keep_inner qualifié.
        let (_, cookies) = r.rules.iter().find(|(q, _)| q == "kbrw/common:cookies").unwrap();
        assert_eq!(cookies.keep_inner.as_deref(), Some(&["kbrw/common:emails".to_string()][..]));
    }

    #[test]
    fn child_adds_overrides_and_disables() {
        let mut lib = Library::default();
        lib.add_str(BASE).unwrap();
        lib.add_str(&child("t/base@^1", "[[rules]]\nid='t/base:emails'\nenabled=false\n[[rules]]\nid='own'\nkeys=['x']\nstrategy='redact'\nlabel='X'\n"))
            .unwrap();
        let r = lib.resolve("t/child").unwrap();
        assert_eq!(r.rules.iter().map(|(q, _)| q.as_str()).collect::<Vec<_>>(), vec!["t/base:emails", "t/base:zip", "t/child:own"]);
        assert_eq!(r.rules[0].1.enabled, Some(false));
        assert_eq!(r.rules[0].1.detector.as_deref(), Some("email"));
    }

    #[test]
    fn errors_are_explicit() {
        let mut lib = Library::default();
        lib.add_str(BASE).unwrap();
        lib.add_str(&child("t/base@^2", "")).unwrap();
        assert!(matches!(lib.resolve("t/child"), Err(CoreError::ParentMissing { .. })));
        lib.add_str(&child("t/absent", "")).unwrap();
        assert!(matches!(lib.resolve("t/child"), Err(CoreError::ParentMissing { .. })));
        lib.add_str(&child("t/base", "[[rules]]\nid='t/base:nope'\nenabled=false\n")).unwrap();
        assert!(matches!(lib.resolve("t/child"), Err(CoreError::Template { .. })));
        lib.add_str(&child("t/child", "")).unwrap();
        assert!(matches!(lib.resolve("t/child"), Err(CoreError::InheritanceCycle(_))));
        assert!(matches!(lib.resolve("t/unknown"), Err(CoreError::TemplateNotFound(_))));
        assert!(lib.add_str("[template]\nid='x/y'\nname='n'\nversion='1.0.0'\nschema_version=9\n").is_err());
    }
}

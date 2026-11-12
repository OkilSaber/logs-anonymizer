//! Templates locaux : `local/<app>`, un fichier TOML par application dans le dossier de
//! données. Le profileur y ajoute des filtres et des règles, par-dessus le template de base.
//! Chaque ajout est validé (compilation du template) avant d'être gardé.

use crate::dto::{LocalAddition, LocalTemplate};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use logano_core::Library;
use std::path::Path;

fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::new("template_invalid", msg)
}

/// En-tête d'un nouveau template local, qui étend le template de base de l'app.
fn new_file(lib: &Library, template_id: &str, app: &str, base: &str) -> AppResult<String> {
    let file = lib.get(base).ok_or_else(|| invalid(format!("Template de base « {base} » introuvable.")))?;
    let resolved = lib.resolve(base)?;
    let format = resolved.format.ok_or_else(|| invalid(format!("Le template « {base} » est abstrait : il ne peut pas servir de base.")))?;
    let major = file.template.version.split('.').next().unwrap_or("1");
    let mut s = format!("# Template local de {app} : filtres et règles ajoutés depuis le profileur.\n# Il étend {base} ; tu peux le modifier à la main.\n\n[template]\n");
    s.push_str(&format!("id = {}\nname = {}\nversion = \"0.1.0\"\nschema_version = 1\n", quoted(template_id), quoted(&format!("{app} (local)"))));
    if let Some(kind) = &file.template.log_kind {
        s.push_str(&format!("log_kind = {}\n", quoted(kind)));
    }
    s.push_str(&format!("format = {}\nextends = [{}]\nsuggested_apps = [{}]\n", quoted(&format), quoted(&format!("{base}@^{major}")), quoted(app)));
    Ok(s)
}

fn block(a: &LocalAddition, id: &str) -> AppResult<String> {
    let mut b = String::from("\n");
    match a.kind.as_str() {
        "filter" => {
            let pattern = a.pattern.as_deref().filter(|p| !p.trim().is_empty()).ok_or_else(|| invalid("Un filtre a besoin d'un motif d'en-tête."))?;
            b.push_str(&format!("[[filters]]\nid = {}\ndescription = {}\naction = \"drop_entry\"\nheader = {}\n", quoted(id), quoted(&a.description), quoted(pattern)));
        }
        "rule" => {
            if a.keys.is_empty() || a.keys.iter().any(|k| k.trim().is_empty()) {
                return Err(invalid("Une règle a besoin d'au moins une clé."));
            }
            let keys = a.keys.iter().map(|k| quoted(k.trim())).collect::<Vec<_>>().join(", ");
            let label = a.label.as_deref().unwrap_or("").trim().to_ascii_uppercase();
            let label_ok = !label.is_empty() && label.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            b.push_str(&format!("[[rules]]\nid = {}\ndescription = {}\nkeys = [{keys}]\n", quoted(id), quoted(&a.description)));
            match a.strategy.as_deref() {
                Some("pseudonymize") if label_ok => b.push_str(&format!("strategy = \"pseudonymize\"\ntoken = {}\n", quoted(&label))),
                Some("redact") if label_ok => b.push_str(&format!("strategy = \"redact\"\nlabel = {}\n", quoted(&label))),
                // Une valeur gardée est protégée des détecteurs à faux positifs.
                Some("keep") => b.push_str("strategy = \"keep\"\npriority = 220\n"),
                Some("pseudonymize" | "redact") => return Err(invalid("Le jeton ou le libellé doit être en majuscules, chiffres et _.")),
                other => return Err(invalid(format!("Stratégie inconnue : « {} ».", other.unwrap_or("")))),
            }
        }
        other => return Err(invalid(format!("Type d'ajout inconnu : « {other} »."))),
    }
    Ok(b)
}

/// Ajoute une valeur à `allowlist.values` : elle ne sera plus masquée, quelle que soit la
/// règle ou le détecteur qui la visait. Le reste du fichier (commentaires, ordre) est conservé.
fn allow_value(content: &str, value: &str) -> AppResult<String> {
    if value.is_empty() || value.len() > 300 || value.contains(['\n', '\r']) {
        return Err(invalid("Valeur à garder invalide : vide, trop longue ou sur plusieurs lignes."));
    }
    let mut doc: toml_edit::DocumentMut = content.parse().map_err(|e| invalid(format!("Le template local n'est plus un TOML valide : {e}")))?;
    let allowlist = doc.entry("allowlist").or_insert(toml_edit::table());
    let table = allowlist.as_table_mut().ok_or_else(|| invalid("[allowlist] n'est pas une table."))?;
    let values = table.entry("values").or_insert(toml_edit::value(toml_edit::Array::new()));
    let array = values.as_array_mut().ok_or_else(|| invalid("allowlist.values n'est pas une liste."))?;
    if !array.iter().any(|v| v.as_str() == Some(value)) {
        array.push(value);
    }
    Ok(doc.to_string())
}

/// Premier identifiant libre de la forme `profil-N`.
fn next_id(content: &str) -> String {
    (1..).map(|n| format!("profil-{n}")).find(|id| !content.contains(&format!("id = {}", quoted(id)))).expect("suite infinie")
}

fn reload(dirs_templates: &Path) -> (Library, Vec<(std::path::PathBuf, logano_core::CoreError)>) {
    let mut lib = Library::builtin();
    let errors = lib.load_dir(dirs_templates);
    (lib, errors)
}

pub fn add(state: &AppState, a: &LocalAddition) -> AppResult<LocalTemplate> {
    let app = a.app.trim();
    if app.is_empty() || !app.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(invalid(format!("Nom d'application invalide : « {app} ».")));
    }
    // Un template local par application et par type de log : celui d'`erlang.log` ne
    // s'applique pas à `haproxy.log`, qui a un autre format.
    let kind = state.library.read().expect("verrou bibliothèque").get(&a.base_template).and_then(|f| f.template.log_kind.clone()).unwrap_or_else(|| "erlang".to_string());
    let template_id = local_id(app, &kind);
    let path = user_path(state, &template_id);
    let previous = std::fs::read_to_string(&path).ok();
    let mut content = match &previous {
        Some(text) => text.clone(),
        None => {
            // Si l'app utilise déjà un template local ailleurs, on ne l'étend pas de lui-même.
            let base = if a.base_template == template_id { "kbrw/elixir" } else { a.base_template.as_str() };
            new_file(&state.library.read().expect("verrou bibliothèque"), &template_id, app, base)?
        }
    };
    let added_id = if a.kind == "allow_value" {
        content = allow_value(&content, a.pattern.as_deref().unwrap_or(""))?;
        "allowlist".to_string()
    } else {
        let id = next_id(&content);
        content.push_str(&block(a, &id)?);
        id
    };

    write_validated(state, &template_id, &path, &content)?;
    Ok(LocalTemplate { template_id, path: path.display().to_string(), added_id })
}

/// Écrit un template de l'utilisateur puis recharge la bibliothèque. S'il ne se charge pas
/// ou ne compile pas, le fichier précédent est restauré : jamais de template invalide sur le disque.
pub fn write_validated(state: &AppState, template_id: &str, path: &Path, content: &str) -> AppResult<()> {
    let previous = std::fs::read_to_string(path).ok();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, content)?;
    let restore = || match &previous {
        Some(text) => std::fs::write(path, text),
        None => std::fs::remove_file(path),
    };
    let (lib, errors) = reload(&state.dirs.user_templates());
    let problem = errors.into_iter().find(|(p, _)| p == path).map(|(_, e)| e).or_else(|| lib.compile(template_id).err());
    if let Some(e) = problem {
        let _ = restore();
        return Err(invalid(format!("Refusé, le template ne serait plus valide : {e}")));
    }
    *state.library.write().expect("verrou bibliothèque") = lib;
    Ok(())
}

/// Recharge la bibliothèque depuis le disque, après une écriture en lot.
pub fn refresh(state: &AppState) {
    let (lib, _) = reload(&state.dirs.user_templates());
    *state.library.write().expect("verrou bibliothèque") = lib;
}

/// Identifiant du template local d'une application pour un type de log :
/// `local/<app>` pour `erlang`, `local/<app>-haproxy`, `local/<app>-console`.
pub fn local_id(app: &str, log_kind: &str) -> String {
    if log_kind == "erlang" {
        format!("local/{app}")
    } else {
        format!("local/{app}-{log_kind}")
    }
}

/// Chemin du fichier d'un template de l'utilisateur : `<données>/templates/<id>.toml`.
pub fn user_path(state: &AppState, template_id: &str) -> std::path::PathBuf {
    state.dirs.user_templates().join(format!("{template_id}.toml"))
}

/// Supprime un template de l'utilisateur et recharge la bibliothèque.
pub fn delete(state: &AppState, template_id: &str) -> AppResult<()> {
    if state.library.read().expect("verrou bibliothèque").is_builtin(template_id) {
        return Err(invalid("Un template fourni avec l'app ne se supprime pas."));
    }
    let path = user_path(state, template_id);
    std::fs::remove_file(&path)?;
    let (lib, _) = reload(&state.dirs.user_templates());
    *state.library.write().expect("verrou bibliothèque") = lib;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(logano_templates), allow(unused_imports, dead_code))]
    use super::*;
    use crate::config::Dirs;
    use crate::state::pick_template;
    use logano_core::template::testing::TEST_KEY;
    use logano_core::{sandbox, Engine, EngineOptions};
    use std::sync::Arc;

    fn state(name: &str) -> (AppState, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("logano-local-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dirs = Dirs { data: root.join("data"), raw_cache: root.join("cache"), default_output: root.join("out") };
        (AppState::init(dirs).unwrap(), root)
    }

    fn addition(kind: &str) -> LocalAddition {
        LocalAddition {
            app: "demo_services".into(),
            base_template: "kbrw/elixir".into(),
            kind: kind.into(),
            description: "Entrée périodique « tick », sans intérêt".into(),
            pattern: Some("\\] +scheduler tick \\d+ for '[^']*'".into()),
            keys: vec![],
            strategy: None,
            label: None,
        }
    }

    fn run(state: &AppState, template: &str, input: &str) -> Vec<(Option<String>, String)> {
        let tpl = Arc::new(state.library.read().unwrap().compile(template).unwrap());
        let engine = Engine::new(tpl, EngineOptions::with_key(TEST_KEY)).unwrap();
        sandbox(&engine, input.as_bytes(), 100).0.into_iter().map(|e| (e.dropped_by, e.out.iter().map(|s| s.text.as_str()).collect())).collect()
    }

    #[cfg(logano_templates)]
    #[test]
    fn a_filter_and_rules_are_added_validated_and_picked_for_the_app() {
        let (state, root) = state("add");
        let added = add(&state, &addition("filter")).unwrap();
        assert_eq!((added.template_id.as_str(), added.added_id.as_str()), ("local/demo_services", "profil-1"));
        assert!(std::path::Path::new(&added.path).ends_with("templates/local/demo_services.toml"));

        let mut rule = addition("rule");
        rule.keys = vec!["nickname".into()];
        rule.strategy = Some("pseudonymize".into());
        rule.label = Some("nick".into());
        assert_eq!(add(&state, &rule).unwrap().added_id, "profil-2");
        let mut keep = addition("rule");
        keep.keys = vec!["basket_id".into()];
        keep.strategy = Some("keep".into());
        assert_eq!(add(&state, &keep).unwrap().added_id, "profil-3");

        // Le template local est celui de l'app, et lui seul.
        let lib = state.library.read().unwrap().clone();
        assert_eq!(pick_template(&lib, &state.config(), "demo_services", "erlang", None).as_deref(), Some("local/demo_services"));
        assert_eq!(pick_template(&lib, &state.config(), "other_services", "erlang", None).as_deref(), Some("kbrw/elixir"));

        let out = run(&state, "local/demo_services", "h.kbrw.fr  10:00:00.000 [info]  scheduler tick 42 for 'orders'\nh.kbrw.fr  10:00:01.000 [info]  x %{nickname: \"Zorro\", basket_id: \"0612345678\", email: \"jean@example.com\"}\n");
        assert_eq!(out[0].0.as_deref(), Some("local/demo_services:profil-1"));
        assert!(out[1].1.contains("nickname: \"NICK_") && out[1].1.contains("basket_id: \"0612345678\"") && out[1].1.contains("email: \"EMAIL_"), "{}", out[1].1);

        // Rechargé depuis le disque, il est toujours là.
        let again = AppState::init(state.dirs.clone()).unwrap();
        assert!(again.library.read().unwrap().get("local/demo_services").is_some());
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(logano_templates)]
    #[test]
    fn an_allowed_value_is_no_longer_replaced_whatever_targeted_it() {
        let (state, root) = state("allow");
        let input = "h.kbrw.fr  10:00:00.000 [info]  [EMAILS TRANSACS] schedule 42 (aB3dE6gH9jK2mN5pQ8sT1vWx) for jean@example.com\nh.kbrw.fr  10:00:01.000 [info]  x %{nickname: \"Zorro\", token: \"zzzz9999\"}\n";
        let before = run(&state, "kbrw/elixir", input);
        assert!(before[0].1.contains("([SECRET])") && before[0].1.contains("EMAIL_"), "{}", before[0].1);

        let allow = |value: &str| {
            let mut a = addition("allow_value");
            a.pattern = Some(value.to_string());
            add(&state, &a)
        };
        assert_eq!(allow("aB3dE6gH9jK2mN5pQ8sT1vWx").unwrap().added_id, "allowlist");
        // Après un filtre ajouté à la main, puis une seconde valeur : le fichier reste valide,
        // la valeur n'est pas doublée.
        add(&state, &addition("filter")).unwrap();
        allow("zzzz9999").unwrap();
        allow("aB3dE6gH9jK2mN5pQ8sT1vWx").unwrap();
        let text = std::fs::read_to_string(state.dirs.user_templates().join("local/demo_services.toml")).unwrap();
        assert_eq!(text.matches("aB3dE6gH9jK2mN5pQ8sT1vWx").count(), 1);
        assert!(text.contains("[allowlist]") && text.contains("[[filters]]") && text.starts_with("# Template local"));

        let after = run(&state, "local/demo_services", input);
        // Les deux valeurs autorisées passent ; le reste est toujours anonymisé.
        assert!(after[0].1.contains("(aB3dE6gH9jK2mN5pQ8sT1vWx)") && after[0].1.contains("EMAIL_") && !after[0].1.contains("jean@"), "{}", after[0].1);
        assert!(after[1].1.contains("token: \"zzzz9999\""), "{}", after[1].1);

        assert!(allow("").is_err() && allow("deux\nlignes").is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(logano_templates)]
    #[test]
    fn each_log_kind_of_an_app_has_its_own_local_template() {
        let (state, root) = state("kinds");
        let mut haproxy = addition("filter");
        haproxy.base_template = "kbrw/haproxy".into();
        haproxy.pattern = Some("SSL handshake failure".into());
        assert_eq!(add(&state, &haproxy).unwrap().template_id, "local/demo_services-haproxy");
        assert_eq!(add(&state, &addition("filter")).unwrap().template_id, "local/demo_services");
        // Un second ajout depuis le template local lui-même retombe sur le même fichier.
        haproxy.base_template = "local/demo_services-haproxy".into();
        assert_eq!(add(&state, &haproxy).unwrap().added_id, "profil-2");
        let lib = state.library.read().unwrap().clone();
        let cfg = state.config();
        assert_eq!(pick_template(&lib, &cfg, "demo_services", "haproxy", None).as_deref(), Some("local/demo_services-haproxy"));
        assert_eq!(pick_template(&lib, &cfg, "demo_services", "erlang", None).as_deref(), Some("local/demo_services"));
        // Rien de local pour le troisième type : le choix habituel s'applique (ici, aucun template).
        assert_eq!(pick_template(&lib, &cfg, "demo_services", "console", None), None);
        assert_eq!(pick_template(&lib, &cfg, "riakn", "console", None).as_deref(), Some("kbrw/riak-console"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(logano_templates)]
    #[test]
    fn an_invalid_addition_is_refused_and_leaves_no_trace() {
        let (state, root) = state("invalid");
        let mut bad = addition("filter");
        bad.pattern = Some("\\] +unclosed (group".into());
        let e = add(&state, &bad).unwrap_err();
        assert_eq!(e.code, "template_invalid");
        assert!(!state.dirs.user_templates().join("local/demo_services.toml").exists());

        // Avec un fichier existant, il est restauré à l'identique.
        add(&state, &addition("filter")).unwrap();
        let path = state.dirs.user_templates().join("local/demo_services.toml");
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(add(&state, &bad).is_err());
        let mut no_label = addition("rule");
        no_label.keys = vec!["x".into()];
        no_label.strategy = Some("redact".into());
        assert!(add(&state, &no_label).is_err());
        let mut bad_app = addition("filter");
        bad_app.app = "../evil".into();
        assert!(add(&state, &bad_app).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert!(state.library.read().unwrap().compile("local/demo_services").is_ok());
        std::fs::remove_dir_all(&root).ok();
    }
}

//! Découverte des apps, des clusters et des fichiers d'un jour.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::error::{RemoteError, Result};
use crate::session::RemoteSession;
use crate::shell::shell_quote;

/// Marqueur écrit sur stderr par nos commandes quand le dossier n'existe pas.
const NO_DIR_MARK: &str = "LOGANO_NO_DIR";

/// Type de fichier de log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    /// `erlang.log` : logs applicatifs Elixir/Erlang.
    Erlang,
    /// `haproxy.log` : logs HAProxy du frontal.
    Haproxy,
    /// `console.log` : logs lager de Riak.
    Console,
}

impl LogKind {
    /// Tous les types, dans l'ordre d'affichage.
    pub const ALL: [LogKind; 3] = [LogKind::Erlang, LogKind::Haproxy, LogKind::Console];

    /// Nom court (`erlang`, `haproxy`, `console`), aussi utilisé dans le cache.
    pub fn as_str(self) -> &'static str {
        match self {
            LogKind::Erlang => "erlang",
            LogKind::Haproxy => "haproxy",
            LogKind::Console => "console",
        }
    }

    /// Reconnaît `erlang.log`, `erlang.log.gz`, etc. Rend le type et si le
    /// fichier est compressé.
    pub fn from_file_name(name: &str) -> Option<(LogKind, bool)> {
        let (stem, compressed) = match name.strip_suffix(".gz") {
            Some(stem) => (stem, true),
            None => (name, false),
        };
        let kind = match stem {
            "erlang.log" => LogKind::Erlang,
            "haproxy.log" => LogKind::Haproxy,
            "console.log" => LogKind::Console,
            _ => return None,
        };
        Some((kind, compressed))
    }
}

/// Une app et ses clusters, tels que trouvés sur le serveur pour un jour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    /// Triés par ordre alphabétique ; peut être vide.
    pub clusters: Vec<String>,
}

/// Un fichier de log distant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFile {
    /// Chemin absolu sur le serveur.
    pub path: String,
    pub kind: LogKind,
    /// Vrai pour un `.gz`.
    pub compressed: bool,
    /// Taille en octets au moment du `stat`.
    pub size: u64,
    /// Date de modification (secondes depuis l'époque Unix).
    pub mtime: i64,
}

/// Motif de chemin découpé autour de `{app_name}/{cluster}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathPattern {
    /// Tout ce qui précède `{app_name}`, sans `/` final.
    prefix: String,
    /// Ce qui suit `{cluster}`, sans `/` de début ni de fin (souvent vide).
    suffix: String,
}

impl PathPattern {
    pub(crate) fn parse(pattern: &str) -> Result<Self> {
        let bad =
            |why: &str| RemoteError::invalid_config(format!("path_pattern « {pattern} » : {why}"));
        if !pattern.starts_with('/') {
            return Err(bad("le chemin doit être absolu"));
        }
        let segments: Vec<&str> = pattern.split('/').collect();
        let app_at = segments
            .iter()
            .position(|s| *s == "{app_name}")
            .ok_or_else(|| bad("le segment {app_name} est absent"))?;
        if segments.get(app_at + 1) != Some(&"{cluster}") {
            return Err(bad("{cluster} doit suivre immédiatement {app_name}"));
        }
        let prefix = segments[..app_at].join("/");
        let suffix = segments[app_at + 2..]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("/");
        for part in [&prefix, &suffix] {
            let rest = part
                .replace("{YYYY}", "")
                .replace("{MM}", "")
                .replace("{DD}", "");
            if rest.contains('{') || rest.contains('}') {
                return Err(bad(
                    "variable inconnue (attendues : {YYYY} {MM} {DD} {app_name} {cluster})",
                ));
            }
        }
        if prefix.is_empty() {
            return Err(bad("{app_name} ne peut pas être à la racine"));
        }
        Ok(PathPattern { prefix, suffix })
    }

    fn with_date(text: &str, day: NaiveDate) -> String {
        text.replace("{YYYY}", &format!("{:04}", day.year()))
            .replace("{MM}", &format!("{:02}", day.month()))
            .replace("{DD}", &format!("{:02}", day.day()))
    }

    /// Dossier qui contient les apps d'un jour (sans `/` final).
    pub(crate) fn apps_root(&self, day: NaiveDate) -> String {
        Self::with_date(&self.prefix, day)
    }

    /// Dossier des fichiers d'une app et d'un cluster (avec `/` final).
    pub(crate) fn files_dir(&self, day: NaiveDate, app: &str, cluster: &str) -> Result<String> {
        check_name("app", app)?;
        check_name("cluster", cluster)?;
        let mut dir = format!("{}/{app}/{cluster}/", self.apps_root(day));
        if !self.suffix.is_empty() {
            dir.push_str(&Self::with_date(&self.suffix, day));
            dir.push('/');
        }
        Ok(dir)
    }
}

/// Refuse les noms qui sortiraient du dossier prévu.
fn check_name(what: &str, name: &str) -> Result<()> {
    let ok = !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0', '\n']);
    if ok {
        Ok(())
    } else {
        Err(RemoteError::invalid_config(format!(
            "nom de {what} invalide : {name:?}"
        )))
    }
}

/// Lit la sortie de `find . -mindepth 1 -maxdepth 2 -type d`.
fn parse_find_output(stdout: &str) -> Vec<AppInfo> {
    let mut apps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in stdout.lines() {
        // Toute ligne qui ne vient pas de `find .` (bannière de shell…) est ignorée.
        let Some(line) = line.strip_prefix("./") else {
            continue;
        };
        let mut parts = line.split('/').filter(|p| !p.is_empty());
        let Some(app) = parts.next() else { continue };
        let clusters = apps.entry(app.to_string()).or_default();
        if let (Some(cluster), None) = (parts.next(), parts.next()) {
            clusters.insert(cluster.to_string());
        }
    }
    apps.into_iter()
        .map(|(name, clusters)| AppInfo {
            name,
            clusters: clusters.into_iter().collect(),
        })
        .collect()
}

/// Lit la sortie de `stat -c '%s %Y %n'`.
fn parse_stat_output(stdout: &str) -> Vec<RemoteFile> {
    let mut files: Vec<RemoteFile> = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ' ');
            let size = parts.next()?.parse().ok()?;
            let mtime = parts.next()?.parse().ok()?;
            let path = parts.next()?;
            let (kind, compressed) = LogKind::from_file_name(path.rsplit('/').next()?)?;
            Some(RemoteFile {
                path: path.to_string(),
                kind,
                compressed,
                size,
                mtime,
            })
        })
        .collect();
    files.sort_by_key(|f| (f.kind, !f.compressed));
    files
}

impl RemoteSession {
    /// Liste les apps et leurs clusters pour un jour, en une seule commande
    /// distante. Dossier du jour absent : [`RemoteError::DayNotFound`].
    pub async fn discover_apps(&self, day: NaiveDate) -> Result<Vec<AppInfo>> {
        let pattern = PathPattern::parse(&self.server().path_pattern)?;
        let root = pattern.apps_root(day);
        let dir = shell_quote(&root);
        let command = format!(
            "if [ -d {dir} ]; then cd {dir} && LC_ALL=C find . -mindepth 1 -maxdepth 2 -type d; \
             else echo {NO_DIR_MARK} >&2; exit 3; fi"
        );
        let out = self.exec(&command).await?;
        if out.exit_status == Some(3) && out.stderr_text().contains(NO_DIR_MARK) {
            return Err(RemoteError::DayNotFound {
                server: self.label(),
                day,
                path: root,
            });
        }
        // Un sous-dossier illisible ne fait pas échouer toute la découverte.
        if !out.success() && out.stdout.is_empty() {
            return Err(RemoteError::CommandFailed {
                server: self.label(),
                exit_status: out.exit_status,
                stderr: out.stderr_text(),
            });
        }
        Ok(parse_find_output(&out.stdout_text()))
    }

    /// Liste les fichiers `erlang.log(.gz)`, `haproxy.log(.gz)` et
    /// `console.log(.gz)` d'une app et d'un cluster, avec taille et date de
    /// modification (`stat -c` GNU). Dossier absent : [`RemoteError::FileNotFound`].
    pub async fn list_files(
        &self,
        day: NaiveDate,
        app: &str,
        cluster: &str,
    ) -> Result<Vec<RemoteFile>> {
        let pattern = PathPattern::parse(&self.server().path_pattern)?;
        let dir = pattern.files_dir(day, app, cluster)?;
        let candidates: Vec<String> = LogKind::ALL
            .iter()
            .flat_map(|kind| {
                let base = format!("{dir}{}.log", kind.as_str());
                [shell_quote(&format!("{base}.gz")), shell_quote(&base)]
            })
            .collect();
        let command = format!(
            "if [ -d {qdir} ]; then LC_ALL=C stat -L -c '%s %Y %n' -- {files}; exit 0; \
             else echo {NO_DIR_MARK} >&2; exit 3; fi",
            qdir = shell_quote(&dir),
            files = candidates.join(" "),
        );
        let out = self.exec(&command).await?;
        let stderr = out.stderr_text();
        if out.exit_status == Some(3) && stderr.contains(NO_DIR_MARK) {
            return Err(RemoteError::FileNotFound {
                server: self.label(),
                path: dir,
            });
        }
        let files = parse_stat_output(&out.stdout_text());
        // `stat` se plaint de chaque fichier absent : c'est attendu. Tout autre
        // message sans aucun résultat signale un vrai problème (stat non GNU…).
        let unexpected: Vec<&str> = stderr
            .lines()
            .filter(|l| !l.contains("No such file or directory") && !l.trim().is_empty())
            .collect();
        if !out.success() || (files.is_empty() && !unexpected.is_empty()) {
            return Err(RemoteError::CommandFailed {
                server: self.label(),
                exit_status: out.exit_status,
                stderr: unexpected.join("\n"),
            });
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_PATH_PATTERN;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 9).unwrap()
    }

    #[test]
    fn motif_par_defaut() {
        let p = PathPattern::parse(DEFAULT_PATH_PATTERN).unwrap();
        assert_eq!(p.apps_root(day()), "/srv/syslog/2026/11/09/APPS");
        assert_eq!(
            p.files_dir(day(), "etam_sb_gateway", "etam-sb").unwrap(),
            "/srv/syslog/2026/11/09/APPS/etam_sb_gateway/etam-sb/"
        );
    }

    #[test]
    fn motif_avec_suffixe_et_jour_a_un_chiffre() {
        let p = PathPattern::parse("/data/{YYYY}-{MM}-{DD}/{app_name}/{cluster}/logs").unwrap();
        let d = NaiveDate::from_ymd_opt(2026, 3, 4).unwrap();
        assert_eq!(p.apps_root(d), "/data/2026-03-04");
        assert_eq!(
            p.files_dir(d, "a", "c").unwrap(),
            "/data/2026-03-04/a/c/logs/"
        );
    }

    #[test]
    fn motifs_invalides() {
        for bad in [
            "srv/{app_name}/{cluster}/",
            "/srv/{YYYY}/{cluster}/",
            "/srv/{app_name}/x/{cluster}/",
            "/srv/{annee}/{app_name}/{cluster}/",
            "/{app_name}/{cluster}/",
        ] {
            assert!(
                PathPattern::parse(bad).is_err(),
                "{bad} devrait être refusé"
            );
        }
    }

    #[test]
    fn noms_dangereux_refuses() {
        let p = PathPattern::parse(DEFAULT_PATH_PATTERN).unwrap();
        for bad in ["", "..", ".", "a/b", "a\nb"] {
            assert!(p.files_dir(day(), bad, "c").is_err());
            assert!(p.files_dir(day(), "a", bad).is_err());
        }
    }

    #[test]
    fn lecture_de_find() {
        let apps = parse_find_output(
            "Bienvenue sur syslogserver01\n./riakn\n./jar_sb_admin/jar-sb-atlas02\n./jar_sb_admin\n./jar_sb_admin/jar-sb-atlas\n./vide\n",
        );
        assert_eq!(
            apps,
            vec![
                AppInfo {
                    name: "jar_sb_admin".into(),
                    clusters: vec!["jar-sb-atlas".into(), "jar-sb-atlas02".into()]
                },
                AppInfo {
                    name: "riakn".into(),
                    clusters: vec![]
                },
                AppInfo {
                    name: "vide".into(),
                    clusters: vec![]
                },
            ]
        );
    }

    #[test]
    fn lecture_de_stat() {
        let files = parse_stat_output(
            "21000000000 1762700000 /srv/a b/haproxy.log\n123 1762600000 /srv/a b/erlang.log.gz\n5 1 /srv/a b/autre.txt\nn'importe quoi\n",
        );
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].kind, LogKind::Erlang);
        assert!(files[0].compressed);
        assert_eq!(files[0].size, 123);
        assert_eq!(files[1].path, "/srv/a b/haproxy.log");
        assert_eq!(files[1].size, 21_000_000_000);
        assert_eq!(files[1].mtime, 1_762_700_000);
        assert!(!files[1].compressed);
    }

    #[test]
    fn noms_de_fichiers() {
        assert_eq!(
            LogKind::from_file_name("console.log.gz"),
            Some((LogKind::Console, true))
        );
        assert_eq!(
            LogKind::from_file_name("erlang.log"),
            Some((LogKind::Erlang, false))
        );
        assert_eq!(LogKind::from_file_name("erlang.log.1"), None);
    }
}

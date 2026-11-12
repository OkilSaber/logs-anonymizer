//! Cache local des fichiers bruts téléchargés.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::discover::{LogKind, RemoteFile};

/// Contenu du `.meta.json` voisin d'un fichier du cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheMeta {
    /// Taille du fichier distant au moment du téléchargement.
    pub remote_size: u64,
    /// Date de modification du fichier distant (secondes Unix).
    pub remote_mtime: i64,
    /// Vrai si le fichier distant était un `.gz` (sinon compressé à la volée).
    #[serde(default)]
    pub remote_compressed: bool,
    /// Vrai une fois le téléchargement terminé.
    pub complete: bool,
    /// Date du téléchargement.
    pub fetched_at: DateTime<Utc>,
}

/// Pourquoi une entrée du cache n'est plus valable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    /// La taille distante a changé (cas du `.log` du jour, qui grossit).
    SizeChanged,
    /// La date de modification distante a changé.
    MtimeChanged,
    /// Le téléchargement précédent n'était pas terminé.
    Incomplete,
    /// Le `.meta.json` existe mais pas le fichier, ou il est illisible.
    Corrupt,
}

/// Réponse de [`RawCache::lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// Le fichier local correspond au fichier distant : pas besoin de retélécharger.
    Valid { path: PathBuf, meta: CacheMeta },
    /// Une entrée existe mais ne correspond plus au fichier distant.
    Stale { path: PathBuf, reason: StaleReason },
    /// Rien en cache.
    Missing,
}

impl CacheLookup {
    /// Vrai si le cache peut être utilisé tel quel.
    pub fn is_valid(&self) -> bool {
        matches!(self, CacheLookup::Valid { .. })
    }
}

/// Ce qu'une purge par taille a retiré.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Evicted {
    pub files: u64,
    pub bytes: u64,
}

/// Cache brut : `<root>/<serveur>/<YYYY>/<MM>/<DD>/<app>/<cluster>/<type>.log.gz`
/// et son `<type>.meta.json`.
#[derive(Debug, Clone)]
pub struct RawCache {
    root: PathBuf,
}

/// Rend un nom utilisable comme dossier : tout caractère hors
/// `[A-Za-z0-9._-]` devient `_`, et `.`/`..`/vide deviennent `_`.
fn safe_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "_".to_string()
    } else {
        cleaned
    }
}

impl RawCache {
    /// Cache enraciné dans `root` (créé à la première écriture).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        RawCache { root: root.into() }
    }

    /// Dossier racine du cache.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir_for(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str) -> PathBuf {
        self.root
            .join(safe_component(server_id))
            .join(format!("{:04}", day.year()))
            .join(format!("{:02}", day.month()))
            .join(format!("{:02}", day.day()))
            .join(safe_component(app))
            .join(safe_component(cluster))
    }

    /// Chemin local du fichier brut (toujours un gzip).
    pub fn path_for(
        &self,
        server_id: &str,
        day: NaiveDate,
        app: &str,
        cluster: &str,
        kind: LogKind,
    ) -> PathBuf {
        self.dir_for(server_id, day, app, cluster)
            .join(format!("{}.log.gz", kind.as_str()))
    }

    /// Chemin du `.meta.json` voisin.
    pub fn meta_path_for(
        &self,
        server_id: &str,
        day: NaiveDate,
        app: &str,
        cluster: &str,
        kind: LogKind,
    ) -> PathBuf {
        self.dir_for(server_id, day, app, cluster)
            .join(format!("{}.meta.json", kind.as_str()))
    }

    /// Dit si l'entrée du cache est valable pour `file` : téléchargement
    /// complet, même taille et même date de modification distantes. Un `.log`
    /// du jour en cours, qui grossit, est donc périmé dès que sa taille change.
    pub fn lookup(
        &self,
        server_id: &str,
        day: NaiveDate,
        app: &str,
        cluster: &str,
        file: &RemoteFile,
    ) -> CacheLookup {
        let path = self.path_for(server_id, day, app, cluster, file.kind);
        let meta_path = self.meta_path_for(server_id, day, app, cluster, file.kind);
        let meta_bytes = match std::fs::read(&meta_path) {
            Ok(bytes) => bytes,
            Err(_) => return CacheLookup::Missing,
        };
        let stale = |reason| CacheLookup::Stale {
            path: path.clone(),
            reason,
        };
        let Ok(meta) = serde_json::from_slice::<CacheMeta>(&meta_bytes) else {
            return stale(StaleReason::Corrupt);
        };
        if !path.is_file() {
            return stale(StaleReason::Corrupt);
        }
        if !meta.complete {
            return stale(StaleReason::Incomplete);
        }
        if meta.remote_size != file.size {
            return stale(StaleReason::SizeChanged);
        }
        if meta.remote_mtime != file.mtime || meta.remote_compressed != file.compressed {
            return stale(StaleReason::MtimeChanged);
        }
        CacheLookup::Valid { path, meta }
    }

    /// Écrit le `.meta.json` d'un fichier. À appeler avec `complete = true`
    /// après un téléchargement réussi vers [`path_for`](Self::path_for).
    pub fn write_meta(
        &self,
        server_id: &str,
        day: NaiveDate,
        app: &str,
        cluster: &str,
        file: &RemoteFile,
        complete: bool,
    ) -> std::io::Result<CacheMeta> {
        let meta = CacheMeta {
            remote_size: file.size,
            remote_mtime: file.mtime,
            remote_compressed: file.compressed,
            complete,
            fetched_at: Utc::now(),
        };
        let meta_path = self.meta_path_for(server_id, day, app, cluster, file.kind);
        if let Some(parent) = meta_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = meta_path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&meta).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(&tmp, &meta_path)?;
        Ok(meta)
    }

    /// Supprime une entrée (fichier, méta et `.part` éventuel).
    pub fn remove(
        &self,
        server_id: &str,
        day: NaiveDate,
        app: &str,
        cluster: &str,
        kind: LogKind,
    ) -> std::io::Result<()> {
        let path = self.path_for(server_id, day, app, cluster, kind);
        let mut part = path.clone().into_os_string();
        part.push(".part");
        for p in [
            path,
            PathBuf::from(part),
            self.meta_path_for(server_id, day, app, cluster, kind),
        ] {
            match std::fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Taille totale du cache en octets (0 s'il n'existe pas encore).
    pub fn size(&self) -> std::io::Result<u64> {
        fn walk(dir: &Path) -> std::io::Result<u64> {
            let mut total = 0;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    total += walk(&entry.path())?;
                } else {
                    total += meta.len();
                }
            }
            Ok(total)
        }
        match walk(&self.root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            other => other,
        }
    }

    /// Vide entièrement le cache.
    /// Ramène le cache sous `max_bytes` en supprimant les fichiers téléchargés les plus
    /// anciens d'abord (et leur méta). Les fichiers listés dans `keep` ne sont jamais
    /// supprimés : ce sont ceux du run en cours ou qui vient de finir.
    pub fn evict_to(&self, max_bytes: u64, keep: &[PathBuf]) -> std::io::Result<Evicted> {
        fn collect(dir: &Path, out: &mut Vec<(std::time::SystemTime, u64, PathBuf)>, total: &mut u64) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                let path = entry.path();
                if meta.is_dir() {
                    collect(&path, out, total)?;
                } else {
                    *total += meta.len();
                    // Seuls les fichiers de logs sont candidats ; leur méta part avec eux.
                    if path.extension().is_some_and(|e| e == "gz") {
                        out.push((meta.modified().unwrap_or(std::time::UNIX_EPOCH), meta.len(), path));
                    }
                }
            }
            Ok(())
        }
        let mut files = Vec::new();
        let mut total = 0u64;
        match collect(&self.root, &mut files, &mut total) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Evicted::default()),
            other => other?,
        }
        files.sort();
        let mut evicted = Evicted::default();
        for (_, len, path) in files {
            if total <= max_bytes {
                break;
            }
            if keep.contains(&path) {
                continue;
            }
            std::fs::remove_file(&path)?;
            // `erlang.log.gz` → `erlang.meta.json`
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let kind = name.split('.').next().unwrap_or(name);
                let _ = std::fs::remove_file(path.with_file_name(format!("{kind}.meta.json")));
            }
            total = total.saturating_sub(len);
            evicted.files += 1;
            evicted.bytes += len;
        }
        Ok(evicted)
    }

    pub fn purge(&self) -> std::io::Result<()> {
        match std::fs::remove_dir_all(&self.root) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 9).unwrap()
    }

    fn remote(size: u64, mtime: i64, compressed: bool) -> RemoteFile {
        RemoteFile {
            path: "/srv/syslog/2026/11/09/APPS/app/c/erlang.log".into(),
            kind: LogKind::Erlang,
            compressed,
            size,
            mtime,
        }
    }

    #[test]
    fn chemins() {
        let cache = RawCache::new("/tmp/raw");
        assert_eq!(
            cache.path_for(
                "etam-sb",
                day(),
                "etam_sb_gateway",
                "etam-sb",
                LogKind::Haproxy
            ),
            PathBuf::from("/tmp/raw/etam-sb/2026/11/09/etam_sb_gateway/etam-sb/haproxy.log.gz")
        );
        assert_eq!(
            cache.meta_path_for(
                "etam-sb",
                day(),
                "etam_sb_gateway",
                "etam-sb",
                LogKind::Haproxy
            ),
            PathBuf::from("/tmp/raw/etam-sb/2026/11/09/etam_sb_gateway/etam-sb/haproxy.meta.json")
        );
        // Aucun composant ne peut sortir de la racine.
        let p = cache.path_for("../x", day(), "..", "a/b", LogKind::Erlang);
        assert_eq!(
            p,
            PathBuf::from("/tmp/raw/.._x/2026/11/09/_/a_b/erlang.log.gz")
        );
    }

    #[test]
    fn lookup_valable_puis_perime() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RawCache::new(dir.path().join("raw"));
        let file = remote(100, 1_762_600_000, false);
        assert_eq!(
            cache.lookup("s", day(), "app", "c", &file),
            CacheLookup::Missing
        );
        assert_eq!(cache.size().unwrap(), 0);

        let path = cache.path_for("s", day(), "app", "c", LogKind::Erlang);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"gzip").unwrap();

        // Téléchargement non terminé.
        cache
            .write_meta("s", day(), "app", "c", &file, false)
            .unwrap();
        assert!(matches!(
            cache.lookup("s", day(), "app", "c", &file),
            CacheLookup::Stale {
                reason: StaleReason::Incomplete,
                ..
            }
        ));

        cache
            .write_meta("s", day(), "app", "c", &file, true)
            .unwrap();
        match cache.lookup("s", day(), "app", "c", &file) {
            CacheLookup::Valid { path: p, meta } => {
                assert_eq!(p, path);
                assert_eq!(meta.remote_size, 100);
                assert!(meta.complete);
            }
            other => panic!("attendu Valid, obtenu {other:?}"),
        }

        // Le .log du jour a grossi.
        assert!(matches!(
            cache.lookup("s", day(), "app", "c", &remote(150, 1_762_600_000, false)),
            CacheLookup::Stale {
                reason: StaleReason::SizeChanged,
                ..
            }
        ));
        // Même taille, date différente.
        assert!(matches!(
            cache.lookup("s", day(), "app", "c", &remote(100, 1_762_600_999, false)),
            CacheLookup::Stale {
                reason: StaleReason::MtimeChanged,
                ..
            }
        ));
        // Le fichier a été remplacé par son .gz après rotation.
        assert!(!cache
            .lookup("s", day(), "app", "c", &remote(100, 1_762_600_000, true))
            .is_valid());

        // Fichier disparu, méta restée.
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            cache.lookup("s", day(), "app", "c", &file),
            CacheLookup::Stale {
                reason: StaleReason::Corrupt,
                ..
            }
        ));
    }

    #[test]
    fn taille_suppression_et_purge() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RawCache::new(dir.path().join("raw"));
        let file = remote(10, 1, true);
        for (app, len) in [("a", 1000usize), ("b", 234)] {
            let path = cache.path_for("s", day(), app, "c", LogKind::Erlang);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, vec![0u8; len]).unwrap();
        }
        assert_eq!(cache.size().unwrap(), 1234);
        cache.write_meta("s", day(), "a", "c", &file, true).unwrap();
        assert!(cache.size().unwrap() > 1234);

        cache.remove("s", day(), "a", "c", LogKind::Erlang).unwrap();
        assert_eq!(
            cache.lookup("s", day(), "a", "c", &file),
            CacheLookup::Missing
        );
        assert_eq!(cache.size().unwrap(), 234);

        cache.purge().unwrap();
        assert_eq!(cache.size().unwrap(), 0);
        assert!(!cache.root().exists());
        cache.purge().unwrap();
    }
    #[test]
    fn evict_removes_the_oldest_downloads_first_and_never_the_kept_ones() {
        let root = std::env::temp_dir().join(format!("logano-cache-evict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let cache = RawCache::new(&root);
        let day = |d: u32| NaiveDate::from_ymd_opt(2026, 11, d).unwrap();
        let mut paths = Vec::new();
        for d in 1..=4u32 {
            let p = cache.path_for("srv", day(d), "app", "cl", LogKind::Erlang);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![0u8; 1000]).unwrap();
            std::fs::write(cache.meta_path_for("srv", day(d), "app", "cl", LogKind::Erlang), b"{}").unwrap();
            // Dates de modification croissantes : le jour 1 est le plus ancien.
            let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + d as u64 * 60);
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(when).unwrap();
            paths.push(p);
        }
        // Sous la limite : rien ne bouge.
        assert_eq!(cache.evict_to(1 << 20, &[]).unwrap(), Evicted::default());
        // 4 fichiers de 1000 octets, limite à 2500 : les deux plus anciens partent, sauf celui qu'on garde.
        let evicted = cache.evict_to(2500, &[paths[0].clone()]).unwrap();
        assert_eq!(evicted, Evicted { files: 2, bytes: 2000 });
        assert!(paths[0].exists() && !paths[1].exists() && !paths[2].exists() && paths[3].exists());
        assert!(!cache.meta_path_for("srv", day(2), "app", "cl", LogKind::Erlang).exists());
        assert!(cache.meta_path_for("srv", day(1), "app", "cl", LogKind::Erlang).exists());
        // Cache absent : pas d'erreur.
        assert_eq!(RawCache::new(root.join("absent")).evict_to(0, &[]).unwrap(), Evicted::default());
        std::fs::remove_dir_all(&root).ok();
    }
}

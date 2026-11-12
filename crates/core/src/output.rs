//! Écriture de la sortie anonymisée : un fichier, ou plusieurs parties d'une taille visée
//! pour tenir dans le contexte d'un LLM. Une partie se termine toujours sur une fin d'entrée.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Estimation du nombre d'octets par token pour des logs (beaucoup de chiffres et de
/// ponctuation). Volontairement basse : mieux vaut une partie un peu trop petite.
pub const BYTES_PER_TOKEN: u64 = 3;

/// Destination des entrées anonymisées.
pub trait EntrySink {
    /// Écrit un bloc d'entrées entières ; `ends` donne la fin de chacune dans `bytes`.
    fn write(&mut self, bytes: &[u8], ends: &[u32]) -> io::Result<()>;
    fn finish(&mut self) -> io::Result<()>;
}

/// Écrit tout à la suite dans un `Write`.
pub struct WriteSink<'a, W: Write>(pub &'a mut W);

impl<W: Write> EntrySink for WriteSink<'_, W> {
    fn write(&mut self, bytes: &[u8], _ends: &[u32]) -> io::Result<()> {
        self.0.write_all(bytes)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Écrit dans `<base>` ou, si une taille de partie est fixée, dans `<nom>.part001.<ext>`,
/// `<nom>.part002.<ext>`… Chaque partie commence par la ligne de contexte courante.
pub struct PartWriter {
    base: PathBuf,
    max_bytes: Option<u64>,
    context: Option<String>,
    file: Option<BufWriter<File>>,
    /// Octets d'entrées dans la partie courante (hors lignes de contexte).
    body: u64,
    written: u64,
    paths: Vec<PathBuf>,
}

impl PartWriter {
    pub fn new(base: impl Into<PathBuf>, max_bytes: Option<u64>) -> Self {
        PartWriter { base: base.into(), max_bytes: max_bytes.filter(|m| *m > 0), context: None, file: None, body: 0, written: 0, paths: Vec::new() }
    }

    fn part_path(&self, n: usize) -> PathBuf {
        if self.max_bytes.is_none() {
            return self.base.clone();
        }
        let stem = self.base.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = self.base.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
        self.base.with_file_name(format!("{stem}.part{n:03}{ext}"))
    }

    fn open_next(&mut self) -> io::Result<()> {
        if let Some(mut f) = self.file.take() {
            f.flush()?;
        }
        let path = self.part_path(self.paths.len() + 1);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut file = BufWriter::with_capacity(1 << 20, File::create(&path)?);
        self.paths.push(path);
        self.body = 0;
        self.written = 0;
        if let Some(ctx) = &self.context {
            let line = if self.max_bytes.is_some() { format!("{ctx} · partie {}\n", self.paths.len()) } else { format!("{ctx}\n") };
            file.write_all(line.as_bytes())?;
            self.written = line.len() as u64;
        }
        self.file = Some(file);
        Ok(())
    }

    /// Change la ligne de contexte (un nouveau jour). Elle est écrite tout de suite dans la
    /// partie en cours, et reprise en tête de chaque partie suivante. `None` : plus de contexte.
    pub fn set_context(&mut self, context: Option<String>) -> io::Result<()> {
        self.context = context;
        if let (Some(file), Some(ctx)) = (self.file.as_mut(), &self.context) {
            file.write_all(ctx.as_bytes())?;
            file.write_all(b"\n")?;
            self.written += ctx.len() as u64 + 1;
        }
        Ok(())
    }

    /// Fichiers écrits jusqu'ici, dans l'ordre.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Supprime tout ce qui a été écrit : jamais de sortie partielle laissée sur le disque.
    pub fn abort(&mut self) {
        self.file = None;
        for p in self.paths.drain(..) {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl EntrySink for PartWriter {
    fn write(&mut self, bytes: &[u8], ends: &[u32]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.file.is_none() {
            self.open_next()?;
        }
        let Some(max) = self.max_bytes else {
            self.body += bytes.len() as u64;
            return self.file.as_mut().expect("fichier ouvert").write_all(bytes);
        };
        let mut start = 0usize;
        for &end in ends {
            let entry = &bytes[start..end as usize];
            start = end as usize;
            // Une entrée plus grosse qu'une partie occupe une partie à elle seule.
            if self.body > 0 && self.written + entry.len() as u64 > max {
                self.open_next()?;
            }
            self.file.as_mut().expect("fichier ouvert").write_all(entry)?;
            self.body += entry.len() as u64;
            self.written += entry.len() as u64;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("logano-output-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn entries(n: usize) -> (Vec<u8>, Vec<u32>) {
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for i in 0..n {
            bytes.extend_from_slice(format!("h  entry {i:03}\n  continuation\n").as_bytes());
            ends.push(bytes.len() as u32);
        }
        (bytes, ends)
    }

    #[test]
    fn single_file_when_no_part_size() {
        let dir = tmp("single");
        let mut w = PartWriter::new(dir.join("erlang.log"), None);
        w.set_context(Some("# jour=2026-11-09".into())).unwrap();
        let (bytes, ends) = entries(5);
        w.write(&bytes, &ends).unwrap();
        w.set_context(Some("# jour=2026-11-10".into())).unwrap();
        w.write(&bytes, &ends).unwrap();
        w.finish().unwrap();
        assert_eq!(w.paths(), &[dir.join("erlang.log")]);
        let text = std::fs::read_to_string(dir.join("erlang.log")).unwrap();
        assert!(text.starts_with("# jour=2026-11-09\nh  entry 000\n"));
        assert_eq!(text.matches("# jour=").count(), 2);
        assert_eq!(text.matches("entry").count(), 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parts_break_on_entry_boundaries_and_repeat_the_context() {
        let dir = tmp("parts");
        let mut w = PartWriter::new(dir.join("erlang.log"), Some(120));
        w.set_context(Some("# app=x · jour=2026-11-09".into())).unwrap();
        let (bytes, ends) = entries(10);
        w.write(&bytes, &ends).unwrap();
        w.finish().unwrap();
        assert!(w.paths().len() >= 3, "{:?}", w.paths());
        assert_eq!(w.paths()[0], dir.join("erlang.part001.log"));
        let mut seen = 0;
        for (i, p) in w.paths().iter().enumerate() {
            let text = std::fs::read_to_string(p).unwrap();
            assert!(text.len() <= 120 + 40, "partie trop grosse : {}", text.len());
            assert!(text.starts_with(&format!("# app=x · jour=2026-11-09 · partie {}\nh  entry", i + 1)), "{text}");
            // Chaque partie finit sur une entrée entière.
            assert!(text.ends_with("  continuation\n"));
            seen += text.matches("h  entry").count();
        }
        assert_eq!(seen, 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn abort_removes_everything() {
        let dir = tmp("abort");
        let mut w = PartWriter::new(dir.join("erlang.log"), Some(60));
        let (bytes, ends) = entries(6);
        w.write(&bytes, &ends).unwrap();
        let paths = w.paths().to_vec();
        assert!(paths.len() > 1 && paths.iter().all(|p| p.exists()));
        w.abort();
        assert!(paths.iter().all(|p| !p.exists()) && w.paths().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}

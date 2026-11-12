//! Téléchargement d'un fichier distant vers un gzip local.

use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::discover::RemoteFile;
use crate::error::{RemoteError, Result};
use crate::session::{ExecStream, RemoteSession};
use crate::shell::shell_quote;

/// Marqueur écrit sur stderr quand la lecture du fichier distant échoue en
/// amont de `gzip` (le statut d'un pipeline ne reflète que sa dernière commande).
const READ_FAILED_MARK: &str = "LOGANO_READ_FAILED";

/// Format du fichier local produit par un téléchargement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    Gzip,
}

/// Résultat d'un téléchargement réussi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadOutcome {
    /// Octets reçus et écrits sur disque (donc compressés).
    pub bytes: u64,
    /// Format du fichier local : toujours gzip.
    pub compressed_as: Compression,
}

/// `<dest>.part` : fichier en cours d'écriture.
fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

impl RemoteSession {
    /// Télécharge `file` dans `dest`, qui sera toujours un gzip :
    ///
    /// - `.gz` : transféré tel quel (`cat`) ;
    /// - `.log` : compressé côté serveur (`gzip -c`), limité à la taille
    ///   relevée par [`list_files`](Self::list_files) ; un fichier qui grossit
    ///   pendant la lecture ne pose donc pas de problème.
    ///
    /// [`ensure_readable`](Self::ensure_readable) est appelé d'abord, avec
    /// `sudo_password`. Les octets sont écrits au fil de l'eau dans
    /// `<dest>.part`, renommé à la fin ; `progress` reçoit le total d'octets
    /// reçus après chaque écriture. En cas d'annulation ([`RemoteError::Cancelled`])
    /// ou d'erreur, ni `dest` ni `<dest>.part` ne restent sur le disque.
    pub async fn download(
        &self,
        file: &RemoteFile,
        dest: &Path,
        sudo_password: Option<&SecretString>,
        progress: impl Fn(u64),
        cancel: CancellationToken,
    ) -> Result<DownloadOutcome> {
        if cancel.is_cancelled() {
            return Err(RemoteError::Cancelled);
        }
        self.ensure_readable(&[file.path.as_str()], sudo_password)
            .await?;

        let quoted = shell_quote(&file.path);
        let command = if file.compressed {
            format!("cat -- {quoted}")
        } else {
            format!(
                "{{ head -c {size} -- {quoted} || echo {READ_FAILED_MARK} >&2; }} | gzip -c",
                size = file.size
            )
        };

        let part = part_path(dest);
        if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| RemoteError::local_io(parent, e))?;
        }
        let mut out = tokio::fs::File::create(&part)
            .await
            .map_err(|e| RemoteError::local_io(&part, e))?;

        let result = async {
            let mut stream = self.exec_stream(&command).await?;
            match receive(&mut stream, &mut out, &part, &progress, &cancel).await {
                Ok(bytes) => {
                    self.check_end(file, &stream, bytes)?;
                    out.flush()
                        .await
                        .map_err(|e| RemoteError::local_io(&part, e))?;
                    out.sync_all()
                        .await
                        .map_err(|e| RemoteError::local_io(&part, e))?;
                    Ok(bytes)
                }
                Err(e) => {
                    // Interrompt `cat` / `gzip` côté serveur.
                    stream.close().await;
                    Err(e)
                }
            }
        }
        .await;
        drop(out);

        match result {
            Ok(bytes) => {
                if let Err(e) = tokio::fs::rename(&part, dest).await {
                    let _ = tokio::fs::remove_file(&part).await;
                    return Err(RemoteError::local_io(dest, e));
                }
                Ok(DownloadOutcome {
                    bytes,
                    compressed_as: Compression::Gzip,
                })
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&part).await;
                Err(e)
            }
        }
    }

    /// Vérifie que la commande distante est allée au bout.
    fn check_end(&self, file: &RemoteFile, stream: &ExecStream, bytes: u64) -> Result<()> {
        let stderr = stream.stderr_text();
        let interrupted = |detail: String| RemoteError::TransferInterrupted {
            path: file.path.clone(),
            detail,
        };
        if stream.exit_status() != Some(0) || stderr.contains(READ_FAILED_MARK) {
            if stderr.contains("No such file or directory") {
                return Err(RemoteError::FileNotFound {
                    server: self.label(),
                    path: file.path.clone(),
                });
            }
            let cleaned = stderr.replace(READ_FAILED_MARK, "").trim().to_string();
            let read_failed = stderr.contains(READ_FAILED_MARK);
            return Err(interrupted(match (stream.exit_status(), stream.signal()) {
                (Some(_), _) if read_failed => {
                    format!("lecture du fichier distant en échec : {cleaned}")
                }
                (Some(code), _) => format!("statut de sortie {code} : {cleaned}"),
                (None, Some(signal)) => format!("commande tuée par le signal {signal}"),
                (None, None) => "flux coupé avant la fin".to_string(),
            }));
        }
        if file.compressed && bytes != file.size {
            return Err(interrupted(format!(
                "{bytes} octets reçus pour {} attendus (le fichier a changé ou le flux a été coupé)",
                file.size
            )));
        }
        Ok(())
    }
}

/// Copie le flux distant dans le fichier local, morceau par morceau.
async fn receive(
    stream: &mut ExecStream,
    out: &mut tokio::fs::File,
    part: &Path,
    progress: &impl Fn(u64),
    cancel: &CancellationToken,
) -> Result<u64> {
    let mut received = 0u64;
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(RemoteError::Cancelled),
            chunk = stream.next_chunk() => chunk?,
        };
        let Some(chunk) = chunk else {
            return Ok(received);
        };
        // L'écriture se fait avant de lire la suite : pas de tampon qui grossit.
        out.write_all(&chunk)
            .await
            .map_err(|e| RemoteError::local_io(part, e))?;
        received += chunk.len() as u64;
        progress(received);
    }
}

//! `sudo chmod +r` avant lecture.

use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretString};

use crate::error::{RemoteError, Result};
use crate::session::RemoteSession;
use crate::shell::quoted_list;

/// Nombre de chemins par commande, pour rester loin de la limite de taille
/// d'une ligne de commande.
const BATCH: usize = 64;

/// Vrai si le stderr de `sudo -n` dit qu'il faut un mot de passe.
fn needs_password(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("password is required")
        || s.contains("terminal is required")
        || s.contains("no tty present")
        || s.contains("askpass")
}

impl RemoteSession {
    /// Rend les fichiers lisibles avec `sudo -n chmod +r -- <fichiers>`.
    ///
    /// - sudo sans mot de passe : rien d'autre à faire ;
    /// - sudo exige un mot de passe et `sudo_password` vaut `None` :
    ///   [`RemoteError::SudoPasswordRequired`] (l'appelant le demande puis rappelle) ;
    /// - avec mot de passe : `sudo -S -p '' chmod +r -- …`, mot de passe passé
    ///   sur stdin, jamais dans la ligne de commande, jamais dans une erreur ;
    /// - refus de sudo ou échec du chmod : [`RemoteError::SudoDenied`] avec le
    ///   stderr, ou [`RemoteError::FileNotFound`] si un fichier n'existe pas.
    pub async fn ensure_readable<S: AsRef<str>>(
        &self,
        paths: &[S],
        sudo_password: Option<&SecretString>,
    ) -> Result<()> {
        for batch in paths.chunks(BATCH) {
            let files = quoted_list(batch);
            let out = self
                .exec(&format!("LC_ALL=C sudo -n chmod +r -- {files}"))
                .await?;
            if out.success() {
                continue;
            }
            let stderr = out.stderr_text();
            if !needs_password(&stderr) {
                return Err(self.chmod_error(stderr, batch));
            }
            let Some(password) = sudo_password else {
                return Err(RemoteError::SudoPasswordRequired {
                    server: self.label(),
                });
            };
            let mut input = password.expose_secret().as_bytes().to_vec();
            input.push(b'\n');
            let result = self
                .exec_with_stdin(
                    &format!("LC_ALL=C sudo -S -p '' chmod +r -- {files}"),
                    Some(&input),
                )
                .await;
            input.zeroize();
            let out = result?;
            if !out.success() {
                // sudo ne répète pas le mot de passe, mais on ne prend aucun risque.
                let mut stderr = out.stderr_text();
                if !password.expose_secret().is_empty() {
                    stderr = stderr.replace(password.expose_secret(), "***");
                }
                return Err(self.chmod_error(stderr, batch));
            }
        }
        Ok(())
    }

    fn chmod_error<S: AsRef<str>>(&self, stderr: String, batch: &[S]) -> RemoteError {
        if stderr.contains("No such file or directory") {
            let path = batch
                .iter()
                .map(|p| p.as_ref())
                .find(|p| stderr.contains(p))
                .or_else(|| batch.first().map(|p| p.as_ref()))
                .unwrap_or_default();
            return RemoteError::FileNotFound {
                server: self.label(),
                path: path.to_string(),
            };
        }
        RemoteError::SudoDenied {
            server: self.label(),
            stderr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::needs_password;

    #[test]
    fn detecte_la_demande_de_mot_de_passe() {
        assert!(needs_password("sudo: a password is required"));
        assert!(needs_password(
            "sudo: a terminal is required to read the password; either use the -S option"
        ));
        assert!(!needs_password(
            "chmod: cannot access 'x': No such file or directory"
        ));
        assert!(!needs_password("jdupont is not in the sudoers file."));
    }
}

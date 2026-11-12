//! Mise à jour de l'app depuis les releases GitHub.
//!
//! Une seule requête sort de l'app : la lecture de `latest.json`, publié avec chaque
//! release. Elle ne porte aucun identifiant. Un paquet téléchargé n'est installé que si sa
//! signature correspond à la clé publique embarquée dans l'app (voir `tauri.conf.json`).

use crate::dto::{UpdateInfo, UpdateProgress};
use crate::error::{AppError, AppResult};
use tauri::AppHandle;
use tauri_plugin_updater::{Update, UpdaterExt};
use tauri_specta::Event;

fn failed(what: &str, e: impl std::fmt::Display) -> AppError {
    AppError::new("update", format!("{what} : {e}"))
}

async fn find(app: &AppHandle) -> AppResult<Option<Update>> {
    let updater = app.updater().map_err(|e| failed("Mise à jour indisponible", e))?;
    updater.check().await.map_err(|e| failed("Impossible de vérifier les mises à jour", e))
}

/// Cherche une version plus récente que celle qui tourne. `None` si l'app est à jour.
pub async fn check(app: &AppHandle) -> AppResult<Option<UpdateInfo>> {
    Ok(find(app).await?.map(|u| UpdateInfo {
        version: u.version.clone(),
        current: u.current_version.clone(),
        notes: u.body.clone().filter(|b| !b.trim().is_empty()),
        date: u.date.map(|d| d.date().to_string()),
    }))
}

/// Télécharge la dernière version, vérifie sa signature, l'installe et relance l'app.
/// Ne rend la main qu'en cas d'erreur, ou si l'app est déjà à jour.
pub async fn install(app: &AppHandle) -> AppResult<()> {
    let Some(update) = find(app).await? else {
        eprintln!("mise à jour : déjà à jour ({})", app.package_info().version);
        return Err(AppError::new("update", "L'app est déjà à jour."));
    };
    eprintln!("mise à jour : {} → {}, téléchargement", update.current_version, update.version);
    let handle = app.clone();
    let (mut downloaded, mut reported) = (0u64, 0u64);
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                // Un événement tous les 256 Kio suffit à la barre de progression.
                if downloaded - reported >= 256 << 10 || Some(downloaded) == total {
                    reported = downloaded;
                    let _ = UpdateProgress { downloaded, total }.emit(&handle);
                }
            },
            || {},
        )
        .await
        .map_err(|e| failed("La mise à jour a échoué, la version en place est gardée", e))?;
    eprintln!("mise à jour : installée, redémarrage");
    app.restart()
}

/// `LOGANO_UPDATE_NOW=1` : met l'app à jour dès le lancement, sans passer par l'interface.
/// Sert au dépannage (une fenêtre qui ne s'affiche plus) et aux tests de la chaîne de release.
pub fn install_at_launch(app: &AppHandle) {
    if std::env::var_os("LOGANO_UPDATE_NOW").is_none() {
        return;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = install(&handle).await {
            eprintln!("mise à jour : {}", e.message);
        }
    });
}

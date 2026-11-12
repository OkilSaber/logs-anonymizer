//! Logs Anonymizer : application desktop.

mod commands;
mod config;
mod dto;
mod error;
mod history;
mod import;
mod local;
mod mapping;
mod runner;
mod state;

use config::Dirs;
use state::AppState;
use tauri::Manager;
use tauri_specta::{collect_commands, collect_events, Builder};

fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .commands(collect_commands![
            commands::get_config,
            commands::save_config,
            commands::import_ssh,
            commands::list_templates,
            commands::run_template_tests,
            commands::template_source,
            commands::template_check,
            commands::template_save,
            commands::template_delete,
            commands::templates_import,
            commands::template_export,
            commands::sandbox_run,
            commands::discover,
            commands::plan_run,
            commands::start_run,
            commands::cancel_run,
            commands::provide_sudo_password,
            commands::provide_key_passphrase,
            commands::preview_output,
            commands::copy_output,
            commands::export_output,
            commands::export_outputs,
            commands::profile_output,
            commands::local_template_add,
            commands::mapping_list,
            commands::mapping_purge,
            commands::deanonymize,
            commands::history_list,
            commands::history_clear,
            commands::cache_info,
            commands::cache_purge,
        ])
        .events(collect_events![dto::RunProgress, dto::RunDone])
        // Tailles et compteurs restent très en dessous de 2^53.
        .dangerously_cast_bigints_to_number()
}

#[cfg(debug_assertions)]
fn bindings_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/src/lib/bindings.ts")
}

pub fn run() {
    let builder = specta_builder();
    #[cfg(debug_assertions)]
    builder.export(specta_typescript::Typescript::default(), bindings_path()).expect("export des types TypeScript");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(builder.invoke_handler())
        .setup(move |app| {
            builder.mount_events(app);
            let path = app.path();
            let dirs = Dirs {
                data: path.app_data_dir()?,
                raw_cache: path.app_cache_dir()?.join("raw"),
                default_output: path.document_dir()?.join("LogsAnonymizer"),
            };
            let state = AppState::init(dirs).map_err(|e| e.message)?;
            app.manage(state);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("erreur au lancement de l'application");
}

#[cfg(test)]
mod tests {
    /// Régénère `ui/src/lib/bindings.ts` sans lancer l'app : `cargo test -p logano-app export_bindings`.
    #[test]
    fn export_bindings() {
        super::specta_builder()
            .export(specta_typescript::Typescript::default(), super::bindings_path())
            .expect("export des types TypeScript");
    }
}

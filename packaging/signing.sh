# Clé de signature des mises à jour. À sourcer depuis les scripts de build.
#
# L'app n'installe une mise à jour que si elle est signée par la clé privée dont la clé
# publique est dans crates/app/tauri.conf.json. La clé privée n'est pas dans le dépôt :
# par défaut ~/.tauri/logs-anonymizer.key (créée avec `cargo tauri signer generate`).
# La perdre, c'est ne plus pouvoir mettre à jour les apps déjà installées.
key="${TAURI_SIGNING_PRIVATE_KEY_PATH:-$HOME/.tauri/logs-anonymizer.key}"
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
  if [ ! -f "$key" ]; then
    echo "Clé de signature introuvable : $key" >&2
    exit 1
  fi
  TAURI_SIGNING_PRIVATE_KEY="$(cat "$key")"
fi
export TAURI_SIGNING_PRIVATE_KEY
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"

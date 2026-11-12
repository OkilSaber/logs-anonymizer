// État partagé de la mise à jour : la barre latérale et les réglages affichent la même chose.
import { api, type UpdateInfo } from "./api";

const messageOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const updater = $state({
  info: null as UpdateInfo | null,
  checking: false,
  /// Une vérification a abouti : « à jour » peut être affiché.
  checked: false,
  installing: false,
  /// Part téléchargée, de 0 à 1 ; `null` tant que la taille n'est pas connue.
  progress: null as number | null,
  error: "",
});

/// Cherche une nouvelle version. `silent` : au démarrage, un échec (hors ligne) ne s'affiche pas.
export async function checkForUpdate(silent = false) {
  if (updater.checking || updater.installing) return;
  updater.checking = true;
  updater.error = "";
  try {
    updater.info = await api.updateCheck();
    updater.checked = true;
  } catch (e) {
    if (!silent) updater.error = messageOf(e);
  } finally {
    updater.checking = false;
  }
}

/// Télécharge et installe la nouvelle version ; l'app redémarre toute seule à la fin.
export async function installUpdate() {
  if (updater.installing) return;
  updater.installing = true;
  updater.progress = null;
  updater.error = "";
  const stop = await api.onUpdateProgress((p) => (updater.progress = p.total ? Math.min(1, p.downloaded / p.total) : null));
  try {
    await api.updateInstall();
  } catch (e) {
    updater.error = messageOf(e);
    updater.installing = false;
  } finally {
    stop();
  }
}

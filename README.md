# Logs Anonymizer

Application desktop (Rust + Tauri 2) qui récupère des logs applicatifs sur des serveurs syslog à travers un bastion SSH, les anonymise selon un template par application, et sort un résultat prêt à donner à une IA.

Règle de base : rien de non anonymisé ne finit dans une sortie. Le cache brut et les sorties sont deux dossiers distincts, et tout ce qui écrit une sortie ne prend que le type `Sanitized`, que seul le moteur peut construire.

Conception détaillée : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Installer

Les binaires sont dans les [releases](../../releases).

| Système | Fichier | Remarques |
|---|---|---|
| macOS 11+ (Apple Silicon et Intel) | `Logs.Anonymizer_<version>_universal.dmg` | L'app n'est pas signée : après l'avoir glissée dans Applications, lancer une fois `xattr -cr "/Applications/Logs Anonymizer.app"`, sinon macOS la dit « endommagée ». |
| Ubuntu 22.04+ (x86_64) | `Logs.Anonymizer_<version>_amd64.AppImage` | `chmod +x` puis lancer. Si elle ne se lance pas : `sudo apt install libfuse2`, ou ajouter l'option `--appimage-extract-and-run`. La table de correspondance utilise le trousseau du bureau (GNOME Keyring, KWallet). |

## Premier lancement : importer les templates

L'app n'embarque qu'un **socle générique** (`base/…`) : il masque ce qui se reconnaît à sa forme (emails, IP, jetons, mots de passe, téléphones, IBAN, cartes) et les clés courantes (noms, adresses, identifiants d'utilisateur). Tout fichier est donc traité et profilable dès l'installation, mais les clés propres à un projet restent en clair et aucun bruit n'est retiré : une sortie faite avec le socle seul est signalée comme telle, et se relit dans **Profil** avant d'être donnée à une IA.

Les templates d'une équipe décrivent les logs de ses applications (bruit à retirer, clés à masquer). Ils se partagent à part, en général dans une archive `.zip`, et passent toujours devant le socle générique.

Dans l'écran **Templates** :

- **Importer…** : un ou plusieurs fichiers `.toml`, ou une ou plusieurs archives `.zip` ;
- **Dossier…** : tous les `.toml` d'un dossier et de ses sous-dossiers.

Un lot peut contenir un template et ses parents, dans n'importe quel ordre, et l'arborescence de l'archive n'a pas d'importance : chaque template est rangé sous son identifiant. Avant d'être enregistré, chaque template est validé (schéma, héritage, compilation) et ses tests embarqués sont lancés. Le rapport d'import liste ce qui est entré, remplacé ou refusé, et signale les templates qui gardent des valeurs en clair ou désactivent une protection héritée : ceux-là sont à relire avant usage.

Les templates importés vont dans le dossier de données de l'app (`~/Library/Application Support/fr.kbrw.logs-anonymizer/templates` sous macOS, `~/.local/share/fr.kbrw.logs-anonymizer/templates` sous Linux). Ils se modifient, s'exportent et se suppriment depuis le même écran.

### Faire écrire un template par une IA

Sans jamais lui donner de logs bruts :

1. Lancer une extraction sur un jour de l'application (le socle générique suffit), ouvrir **Profil** sur le résultat, puis **Copier pour une IA** : formes de lignes les plus lourdes et clés qui gardent des valeurs en clair, sans aucune valeur.
2. Donner à l'IA ce profil, un template existant comme modèle (**Templates** → **Exporter…**) et la section 8 de [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
3. Coller le TOML dans **Templates** → **Nouveau** : il est validé en direct et ses tests sont lancés. L'essayer dans le **Bac à sable**, enregistrer, puis relancer **Profil** pour vérifier que les clés visées ne sont plus en clair.

Ensuite, dans **Réglages** : le bastion et les serveurs syslog, à la main ou avec « Importer depuis ma config SSH » (lit `~/.ssh/config`, les alias `*logs` de `~/.zshrc` et les commandes `ssh … syslogserver…` de l'historique du shell).

## Ce que fait l'app

- **Extraction** : plages de jours, plan avec tailles et estimation disque, téléchargements et anonymisation en parallèle (réglable, 1 à 8 fichiers chacun), progression par fichier, une sortie par jour, statistiques, vue côte à côte, copie par partie, export d'un jour ou de tous les jours d'une application.
- **Moteur** : formats `elixir_syslog`, `haproxy_syslog` et `lager_syslog` ; extracteurs (métadonnées Plug, cookies, JSON, termes Elixir, requêtes HTTP, HAProxy, clés Riak) ; douze détecteurs (emails, jetons, IP, téléphones, IBAN, cartes, secrets à forte entropie…) ; stratégies (pseudonymiser, masquer, garder, retirer) ; filet de sécurité qui repasse tous les détecteurs sur la sortie.
- **Templates** : héritage, tests embarqués, filtres de bruit, règles par clé, route, expression régulière ou détecteur ; éditeur avec validation en direct ; import en lot et export.
- **Profil** : formes d'entrées par poids et inventaire des clés d'un fichier, sans jamais lire une valeur ; un clic ajoute un filtre ou une règle au template local de l'application (`local/<app>`), et « Copier pour une IA » met le profil dans le presse-papier pour faire écrire un template.
- **Bac à sable** : coller un extrait, voir ce que le template en fait.
- **Table de correspondance** chiffrée (clé dans le trousseau du système) et écran « Réponse IA » pour remettre les vraies valeurs dans la réponse.
- **Historique** des runs, rejouable.

Ce qui reste sur la machine : le mot de passe `sudo` et la phrase de passe de la clé ne sont gardés qu'en mémoire. Hors SSH, l'app n'ouvre qu'une connexion : la vérification des mises à jour, décrite ci-dessous, qui se désactive.

## Mises à jour

Au démarrage, l'app lit `latest.json` dans la dernière release GitHub du projet. S'il annonce une version plus récente, la barre latérale propose « Installer et redémarrer » : le paquet est téléchargé, sa signature vérifiée avec la clé publique embarquée dans l'app, puis l'app est remplacée et relancée. Une mise à jour faite ainsi n'a pas besoin du `xattr` de l'installation.

- La requête ne porte aucun identifiant, et rien d'autre n'est envoyé.
- **Réglages → Mises à jour** : décocher « Chercher une nouvelle version au démarrage » pour que l'app ne contacte plus que les serveurs SSH ; « Vérifier maintenant » reste disponible.
- `LOGANO_UPDATE_NOW=1` au lancement met l'app à jour sans passer par l'interface.
- La version 0.1.0 n'a pas ce mécanisme : il faut installer une fois la 0.1.1 ou plus à la main.

## Organisation du dépôt

| Dossier | Contenu |
|---|---|
| `crates/core` | Moteur : formats, assemblage, extracteurs, détecteurs, règles, stratégies, filet de sécurité, templates. Aucune dépendance Tauri ni tokio. |
| `crates/remote` | SSH via bastion (`nc` ou `direct-tcpip`), `sudo chmod +r`, découverte, téléchargement, cache brut, import de la config SSH. Voir [crates/remote/README.md](crates/remote/README.md). |
| `crates/app` | App Tauri : commandes typées, orchestration d'un run, import de templates. |
| `ui` | Interface Svelte 5 + TypeScript + Tailwind 4. `ui/src/lib/bindings.ts` est généré depuis Rust. |
| `packaging` | Scripts de build des binaires distribués (macOS, Linux). |

Le socle générique est dans `crates/core/templates/base/`. Les templates d'équipe (`templates/`) et leur corpus de test (`corpus/`) ne sont pas dans le dépôt.

## Développer

Prérequis : Rust stable, Node 20+, `cargo install tauri-cli --version "^2"`, et les [dépendances système de Tauri](https://tauri.app/start/prerequisites/).

```sh
cd ui && npm install                 # une fois
cd crates/app && cargo tauri dev
```

L'interface seule, avec des données de démonstration et sans backend : `cd ui && npm run dev`.

### Tests

```sh
cargo test --workspace
cd ui && npx svelte-check
```

Sans le dossier `templates/`, les tests qui s'appuient sur des templates réels (corpus golden, tests des templates, une partie des tests du moteur) ne sont pas compilés ; le reste passe. Avec `templates/` et `corpus/` posés à la racine du dépôt, toute la suite tourne. Après avoir ajouté ou retiré ces dossiers, forcer la détection : `touch crates/core/build.rs crates/app/build.rs`.

Les tests SSH lancent des serveurs SSH en processus (bastion + cibles), sans Docker. Ceux qui visent de vrais `sshd` sont dans `crates/remote/docker`, derrière la fonctionnalité `docker-tests`.

Outils de développement (ils chargent les templates de `templates/`) :

```sh
cargo run -p logano-core --example template_tests -- <template>            # sorties des tests d'un template
cargo run --release -p logano-core --example profile -- <template> <fichier>
cargo run --release -p logano-core --example anonymize -- <template> compact <sortie> <entrée>...
cargo run --release -p logano-core --example throughput -- 512             # débit du moteur sur 512 Mo
cargo test -p logano-app export_bindings                                   # régénérer les types TypeScript
```

### Templates embarqués ou non

Le socle générique `base/…` est toujours embarqué. En plus, `logano-core` a une fonctionnalité `embedded-templates` (activée par défaut pour ses propres tests et outils) qui embarque à la compilation les `.toml` de `templates/`, s'il existe. L'app (`logano-app`) dépend du moteur **sans** cette fonctionnalité : `cargo tauri dev` et `cargo tauri build` ne contiennent donc que le socle générique, qu'il y ait un dossier `templates/` ou non.

## Construire les binaires

macOS, application universelle et `.dmg` :

```sh
packaging/macos/build.sh
# → target/universal-apple-darwin/release/bundle/dmg/*.dmg
```

Linux, AppImage construite dans Docker (Ubuntu 22.04) à partir du dernier commit :

```sh
packaging/linux/build.sh          # x86_64 ; « arm64 » en argument pour ARM
# → dist/linux/*.AppImage
```

Les deux scripts retirent les symboles de debug ; celui de macOS retire aussi les chemins de la machine de build.

### Publier une version

1. Monter la version dans `Cargo.toml`, `crates/app/tauri.conf.json` et `ui/package.json`.
2. `packaging/macos/build.sh`, puis `packaging/linux/build.sh`.
3. `packaging/release.sh` rassemble les fichiers dans `dist/release/` et écrit `latest.json`.
4. `gh release create v<version> dist/release/*`. La release ne doit être ni un brouillon ni une pré-version : l'app lit `releases/latest/download/latest.json`.

Les builds signent les paquets de mise à jour avec la clé privée `~/.tauri/logs-anonymizer.key` (ou `TAURI_SIGNING_PRIVATE_KEY`). Elle n'est pas dans le dépôt. Sa clé publique est dans `crates/app/tauri.conf.json` ; sans la clé privée, on ne peut plus publier de mise à jour que les apps installées acceptent.

## Pas encore fait

SFTP et reprise d'un téléchargement interrompu ; segments et rafraîchissement par delta du jour en cours ; vues décodées (un email URL-encodé en `%40` n'est pas vu) ; éditeur de règles en mode formulaire ; coloration du TOML ; formes inconnues signalées pendant un run ; export d'un corpus de fixtures ; signature et notarisation de l'app macOS.

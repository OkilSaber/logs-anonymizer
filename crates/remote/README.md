# logano-remote

Accès aux serveurs syslog à travers un bastion SSH : connexion, `sudo chmod +r`,
découverte des apps et des fichiers d'un jour, téléchargement vers un gzip
local, cache brut, import de `~/.ssh/config`.

Tout passe par des **canaux exec** (`russh`). Pas de SFTP dans ce MVP.

## Exemple

```rust
use logano_remote::*;

let pool = SessionPool::new(bastion, ConnectOptions::default());
let session = pool.session(&server).await?;              // Arc<RemoteSession>, réutilisé ensuite

let apps = session.discover_apps(day).await?;            // Vec<AppInfo>
let files = session.list_files(day, "etam_sb_gateway", "etam-sb").await?;

let cache = RawCache::new(cache_root);
for file in &files {
    if cache.lookup(&server.id, day, app, cluster, file).is_valid() {
        continue;
    }
    let dest = cache.path_for(&server.id, day, app, cluster, file.kind);
    match session.download(file, &dest, sudo_password.as_ref(), |received| { /* progression */ }, cancel.clone()).await {
        Ok(_) => { cache.write_meta(&server.id, day, app, cluster, file, true)?; }
        Err(RemoteError::SudoPasswordRequired { .. }) => { /* demander le mot de passe, puis rappeler */ }
        Err(e) => return Err(e),
    }
}
pool.close().await;
```

## API publique

Tout est exporté à la racine de la crate. `Result<T>` vaut `Result<T, RemoteError>`.
`SecretString` (`secrecy`) et `CancellationToken` (`tokio_util`) sont réexportés.

### Configuration (`Serialize + Deserialize + Clone + Debug + PartialEq`)

```rust
pub struct BastionConfig {
    pub host: String,
    pub port: u16,                       // défaut 22
    pub user: String,
    pub auth: AuthConfig,                // défaut Key { "~/.ssh/id_rsa" }
    pub mode: JumpMode,                  // défaut Nc
    pub nc_command: String,              // défaut "nc {host} {port}"
    pub host_key_policy: HostKeyPolicy,  // défaut Insecure ; vaut aussi pour les cibles
    pub keepalive_secs: u64,             // défaut 60 ; 0 = désactivé
}
impl BastionConfig { pub fn new(host: impl Into<String>, user: impl Into<String>) -> Self }

pub struct ServerConfig {
    pub id: String,                      // sert de dossier dans le cache
    pub name: String,
    pub host: String,
    pub port: u16,                       // défaut 22
    pub user: Option<String>,            // None = celui du bastion utilisé
    pub auth: Option<AuthConfig>,        // None = celle du bastion utilisé
    pub bastion: Option<BastionConfig>,  // None = bastion global du pool
    pub path_pattern: String,            // défaut DEFAULT_PATH_PATTERN
}
impl ServerConfig {
    pub fn new(id: impl Into<String>, name: impl Into<String>, host: impl Into<String>) -> Self;
    pub fn effective_bastion<'a>(&'a self, global: &'a BastionConfig) -> &'a BastionConfig;
    pub fn effective_user<'a>(&'a self, global: &'a BastionConfig) -> &'a str;
    pub fn effective_auth<'a>(&'a self, global: &'a BastionConfig) -> &'a AuthConfig;
}

pub enum AuthConfig { Key { identity_file: String }, Agent }   // `~` étendu à la connexion
pub enum JumpMode { Nc, DirectTcpip }
pub enum HostKeyPolicy { Insecure, Tofu }

pub const DEFAULT_PATH_PATTERN: &str = "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/";
pub const DEFAULT_NC_COMMAND: &str = "nc {host} {port}";
pub const DEFAULT_IDENTITY_FILE: &str = "~/.ssh/id_rsa";
pub fn expand_tilde(path: &str) -> PathBuf;
```

Forme sérialisée (celle de `docs/ARCHITECTURE.md` §12) : `auth` et
`identity_file` sont **à plat**, pas dans une sous-table.

```toml
[bastion]
host = "access01.cloud.kbrwadventure.com"
user = "jdupont"
auth = "key"                      # key | agent ; absent = key
identity_file = "~/.ssh/id_rsa"   # absent = ~/.ssh/id_rsa
mode = "nc"                       # nc | direct_tcpip
nc_command = "nc {host} {port}"
host_key_policy = "insecure"      # insecure | tofu
keepalive_secs = 60

[[servers]]
id = "etam-sb"
name = "Etam — sandbox"
host = "syslogserver01.priv.etamadm-sb.kbrw.fr"
# user, auth, identity_file, [servers.bastion] : facultatifs
```

`path_pattern` : chemin absolu ; `{cluster}` doit suivre immédiatement
`{app_name}` ; variables reconnues : `{YYYY}` `{MM}` `{DD}` `{app_name}` `{cluster}`.

### Connexion

```rust
pub struct ConnectOptions {
    pub known_hosts_path: Option<PathBuf>,  // fichier JSON du TOFU ; obligatoire si policy = Tofu
    pub connect_timeout: Duration,          // défaut 20 s (connexion + authentification)
}   // impl Default, Clone

pub struct SessionPool;                     // Send + Sync, à mettre dans un Arc
impl SessionPool {
    pub fn new(bastion: BastionConfig, options: ConnectOptions) -> Self;
    pub fn bastion(&self) -> &BastionConfig;
    pub fn set_key_passphrase(&self, identity_file: &str, passphrase: Option<SecretString>);
    pub async fn session(&self, server: &ServerConfig) -> Result<Arc<RemoteSession>>;
    pub async fn close(&self);
    pub fn stats(&self) -> PoolStats;
}
pub struct PoolStats { pub bastion_connections: usize, pub target_connections: usize }
```

- `session` ouvre le bastion au premier appel, puis une session par serveur
  (clé : `ServerConfig::id`). Deux appels pour le même serveur rendent le même
  `Arc` ; une session morte, ou une config de serveur modifiée, provoque une
  reconnexion. Un seul bastion par couple utilisateur/hôte/port, même avec des
  appels simultanés.
- Clé chiffrée : `session` rend `KeyPassphraseRequired { identity_file }` ;
  appeler `set_key_passphrase(identity_file, Some(...))` puis recommencer.
  `KeyPassphraseInvalid` si elle est fausse. La clé déchiffrée est gardée en mémoire.
- TOFU : l'empreinte SHA-256 est enregistrée au premier contact dans
  `known_hosts_path` (clé `hôte:port`) ; si elle change : `HostKeyChanged`.

### Session

```rust
pub struct RemoteSession;                   // Send + Sync ; un canal par commande, parallélisable
impl RemoteSession {
    pub fn server(&self) -> &ServerConfig;
    pub fn is_alive(&self) -> bool;
    pub async fn close(&self);

    pub async fn exec(&self, command: &str) -> Result<ExecOutput>;
    pub async fn exec_with_stdin(&self, command: &str, stdin: Option<&[u8]>) -> Result<ExecOutput>;
    pub async fn exec_stream(&self, command: &str) -> Result<ExecStream>;

    pub async fn ensure_readable<S: AsRef<str>>(&self, paths: &[S], sudo_password: Option<&SecretString>) -> Result<()>;

    pub async fn discover_apps(&self, day: NaiveDate) -> Result<Vec<AppInfo>>;
    pub async fn list_files(&self, day: NaiveDate, app: &str, cluster: &str) -> Result<Vec<RemoteFile>>;

    pub async fn download(
        &self,
        file: &RemoteFile,
        dest: &Path,
        sudo_password: Option<&SecretString>,
        progress: impl Fn(u64),             // total d'octets reçus, après chaque écriture
        cancel: CancellationToken,
    ) -> Result<DownloadOutcome>;
}

pub struct ExecOutput { pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub exit_status: Option<u32> }
impl ExecOutput {
    pub fn success(&self) -> bool;          // exit_status == Some(0)
    pub fn stdout_text(&self) -> String;
    pub fn stderr_text(&self) -> String;
}

pub struct ExecStream;                      // stdout au fil de l'eau
impl ExecStream {
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>>;  // None = terminé
    pub fn exit_status(&self) -> Option<u32>;
    pub fn signal(&self) -> Option<&str>;
    pub fn stderr(&self) -> &[u8];          // tronqué à 64 Kio
    pub fn stderr_text(&self) -> String;
    pub async fn close(self);               // interrompt la commande distante
}

pub fn shell_quote(s: &str) -> String;      // 'a'\''b' ; à utiliser pour tout chemin passé à exec
```

- `exec` : un statut non nul n'est **pas** une erreur, il est dans `exit_status`.
  stdin est toujours fermé après l'envoi éventuel de `stdin`.
- `ensure_readable` : `sudo -n chmod +r -- <fichiers>` (par lots de 64). Si sudo
  veut un mot de passe et que `sudo_password` vaut `None` : `SudoPasswordRequired`.
  Sinon `sudo -S -p '' chmod +r -- …`, mot de passe sur stdin uniquement.
  Mauvais mot de passe ou refus : `SudoDenied { stderr }`. Fichier absent : `FileNotFound`.
- `discover_apps` : une seule commande (`find . -mindepth 1 -maxdepth 2 -type d`
  dans `…/APPS`). Apps et clusters triés. Dossier absent : `DayNotFound`.
- `list_files` : une seule commande (`stat -L -c '%s %Y %n'`, GNU). Rend les
  `erlang|haproxy|console.log(.gz)` présents, `.gz` d'abord. Dossier absent : `FileNotFound`.
- `download` : appelle `ensure_readable`, puis `cat` pour un `.gz`, ou
  `head -c <size> | gzip -c` pour un `.log` (taille figée à celle du `stat` : un
  fichier qui grossit ne gêne pas). Le fichier local est **toujours un gzip**.
  Écrit `<dest>.part` au fil de l'eau puis renomme. Annulation : `Cancelled`.
  Statut non nul, flux coupé, ou taille reçue ≠ `file.size` pour un `.gz` :
  `TransferInterrupted`. Dans tous les cas d'échec, ni `dest` ni `.part` ne restent.

```rust
pub struct AppInfo { pub name: String, pub clusters: Vec<String> }
pub struct RemoteFile { pub path: String, pub kind: LogKind, pub compressed: bool, pub size: u64, pub mtime: i64 }
pub enum LogKind { Erlang, Haproxy, Console }
impl LogKind {
    pub const ALL: [LogKind; 3];
    pub fn as_str(self) -> &'static str;                             // "erlang" | "haproxy" | "console"
    pub fn from_file_name(name: &str) -> Option<(LogKind, bool)>;    // (type, compressé)
}
pub struct DownloadOutcome { pub bytes: u64, pub compressed_as: Compression }
pub enum Compression { Gzip }
```

`AppInfo`, `RemoteFile`, `LogKind`, `Compression` sont `Serialize + Deserialize`
(`LogKind` et `Compression` en `snake_case`).

### Cache brut

`<root>/<serveur>/<YYYY>/<MM>/<DD>/<app>/<cluster>/<type>.log.gz` et son
`<type>.meta.json`. Fonctions synchrones (E/S disque courtes).

```rust
pub struct RawCache;                        // Clone
impl RawCache {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    pub fn root(&self) -> &Path;
    pub fn path_for(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str, kind: LogKind) -> PathBuf;
    pub fn meta_path_for(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str, kind: LogKind) -> PathBuf;
    pub fn lookup(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str, file: &RemoteFile) -> CacheLookup;
    pub fn write_meta(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str, file: &RemoteFile, complete: bool) -> std::io::Result<CacheMeta>;
    pub fn remove(&self, server_id: &str, day: NaiveDate, app: &str, cluster: &str, kind: LogKind) -> std::io::Result<()>;
    pub fn size(&self) -> std::io::Result<u64>;
    pub fn purge(&self) -> std::io::Result<()>;
}
pub enum CacheLookup {
    Valid { path: PathBuf, meta: CacheMeta },
    Stale { path: PathBuf, reason: StaleReason },
    Missing,
}
impl CacheLookup { pub fn is_valid(&self) -> bool }
pub enum StaleReason { SizeChanged, MtimeChanged, Incomplete, Corrupt }
pub struct CacheMeta {
    pub remote_size: u64,
    pub remote_mtime: i64,
    pub remote_compressed: bool,
    pub complete: bool,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}
```

`lookup` est `Valid` si le méta est complet, que le fichier local existe, et que
la taille, la date de modification et le caractère compressé du fichier distant
n'ont pas changé. Le `.log` du jour, qui grossit, devient donc `Stale` dès que
sa taille change. Le cache n'écrit pas le méta tout seul : appeler `write_meta`
après un `download` réussi.

### Import

```rust
pub fn import_ssh_config(ssh_config_text: &str, zshrc_text: &str, history_text: &str) -> ImportProposal;
pub struct ImportProposal { pub bastion: Option<BastionConfig>, pub servers: Vec<ServerConfig> }
```

Fonction pure (prend le texte des fichiers). Serveurs retenus : alias zsh dont
le nom finit par `logs` et qui lancent `ssh <hôte>`, et entrées `Host` littérales
dont le nom ou le `HostName` commence par `syslogserver`. Le bastion vient de
`ProxyCommand ssh user@bastion "nc %h %p"` (mode `nc`), de
`ProxyCommand ssh -W %h:%p bastion` ou de `ProxyJump` (mode `direct_tcpip`).
`syslogserver01.priv.etamadm-sb.kbrw.fr` donne l'id `etam-sb` et le nom
`Etam — sandbox`. Les champs `user`, `auth`, `bastion` d'un serveur ne sont
remplis que s'ils diffèrent du bastion global proposé.

### Erreurs

`RemoteError` (`thiserror`, messages en français, jamais de secret).
`RemoteError::code()` rend un identifiant stable pour l'interface.

| Variante | `code()` | Quand |
|---|---|---|
| `BastionUnreachable { host, port, detail }` | `bastion_unreachable` | bastion injoignable, délai dépassé |
| `TargetUnreachable { host, port, detail }` | `target_unreachable` | `nc` ou `direct-tcpip` n'atteint pas la cible |
| `KeyRejected { host, user }` | `key_rejected` | clé (ou toutes les clés de l'agent) refusée |
| `KeyPassphraseRequired { identity_file }` | `key_passphrase_required` | clé chiffrée, pas de phrase de passe |
| `KeyPassphraseInvalid { identity_file }` | `key_passphrase_invalid` | phrase de passe fausse |
| `KeyUnreadable { identity_file, detail }` | `key_unreadable` | fichier de clé absent ou illisible |
| `AgentUnavailable { detail }` | `agent_unavailable` | `SSH_AUTH_SOCK` absent, agent vide |
| `HostKeyChanged { host, port, expected, actual }` | `host_key_changed` | TOFU : empreinte différente |
| `SudoPasswordRequired { server }` | `sudo_password_required` | sudo veut un mot de passe, aucun fourni |
| `SudoDenied { server, stderr }` | `sudo_denied` | mauvais mot de passe, refus, chmod en échec |
| `DayNotFound { server, day, path }` | `day_not_found` | dossier du jour absent |
| `FileNotFound { server, path }` | `file_not_found` | fichier ou dossier absent |
| `TransferInterrupted { path, detail }` | `transfer_interrupted` | flux coupé, statut non nul, taille inattendue |
| `Cancelled` | `cancelled` | annulation par le `CancellationToken` |
| `LocalIo { path, source }` | `local_io` | erreur disque locale |
| `CommandFailed { server, exit_status, stderr }` | `command_failed` | autre échec d'une commande distante |
| `SessionLost { server, detail }` | `session_lost` | session tombée pendant une opération |
| `InvalidConfig { detail }` | `invalid_config` | `path_pattern` invalide, TOFU sans fichier, nom d'app invalide |

## Limites connues de ce MVP

- Pas de SFTP, pas de reprise, pas de `zstd`, pas de segments de 256 Mo, pas de
  rafraîchissement par delta du jour en cours (prévus dans `docs/ARCHITECTURE.md` §9).
- Le cache n'a ni taille maximale ni purge LRU : seulement `size()`, `remove()`, `purge()`.
- En mode `nc`, chaque serveur ouvert occupe un canal session sur le bastion.
  OpenSSH en accepte 10 par connexion par défaut (`MaxSessions`) : au-delà de
  10 serveurs ouverts en même temps, l'ouverture échouera.
- Le mot de passe sudo n'est pas mémorisé par la crate : l'appelant le garde
  (par serveur) et le repasse à `ensure_readable` / `download`.
- Les commandes distantes supposent un Linux GNU (`stat -c`, `find -mindepth`,
  `head -c`, `chmod +r --`).

## Tests

```sh
cargo test -p logano-remote
```

Hermétiques, sans Docker : `tests/common/mod.rs` lance des serveurs SSH **en
processus** (côté serveur de `russh`) sur 127.0.0.1, un « bastion » et deux
« cibles », dont les exec lancent `sh -c` avec un `PATH` préfixé par un dossier
de faux binaires : un faux `sudo` (modes `nopasswd` / `password:<secret>`), et,
sur macOS seulement, une émulation de `stat -c` et de `chmod +r --` GNU. Le mode
`nc` lance le vrai `nc` de la machine depuis le canal exec du bastion.
`tests/ssh_agent.rs` lance un vrai `ssh-agent` ; le test RSA utilise `ssh-keygen`
(les deux se sautent si l'outil manque).

Contre de vrais `sshd` (non lancés par défaut) :

```sh
cd crates/remote
./docker/gen-keys.sh
docker compose -f docker/docker-compose.yml up -d --build
cargo test -p logano-remote --features docker-tests --test docker_ssh
docker compose -f docker/docker-compose.yml down
```

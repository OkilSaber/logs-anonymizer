//! Banc de test hermétique : serveurs SSH en processus (côté serveur de
//! `russh`), faux `sudo`, émulation de `stat -c` et de `chmod +r --` GNU sur
//! macOS, arborescence
//! `…/{YYYY}/{MM}/{DD}/APPS/{app}/{cluster}/` dans un dossier temporaire.
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::NaiveDate;
use logano_remote::{
    AuthConfig, BastionConfig, ConnectOptions, JumpMode, ServerConfig, SessionPool,
};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure, Disconnect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Jour présent dans l'arborescence de test.
pub fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 11, 9).unwrap()
}

/// Empêche un test bloqué de figer toute la suite.
pub async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), future)
        .await
        .expect("test trop long (60 s)")
}

pub fn new_key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

// ---------------------------------------------------------------------------
// Serveur SSH en processus
// ---------------------------------------------------------------------------

struct State {
    host_key: Mutex<PrivateKey>,
    authorized: Mutex<Vec<PublicKey>>,
    /// Variables d'environnement des commandes exécutées (dont `PATH`).
    env: Vec<(String, String)>,
    allow_direct_tcpip: bool,
    connections: AtomicUsize,
    auth_algorithms: Mutex<Vec<String>>,
    commands: Mutex<Vec<String>>,
    handles: Mutex<Vec<server::Handle>>,
}

/// Un serveur SSH qui écoute sur 127.0.0.1 et exécute les commandes reçues
/// avec `sh -c`, dans un environnement contrôlé.
pub struct TestServer {
    pub port: u16,
    state: Arc<State>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    pub async fn start(
        authorized: Vec<PublicKey>,
        env: Vec<(String, String)>,
        allow_direct_tcpip: bool,
    ) -> TestServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State {
            host_key: Mutex::new(new_key()),
            authorized: Mutex::new(authorized),
            env,
            allow_direct_tcpip,
            connections: AtomicUsize::new(0),
            auth_algorithms: Mutex::new(Vec::new()),
            commands: Mutex::new(Vec::new()),
            handles: Mutex::new(Vec::new()),
        });
        let accept_state = state.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let state = accept_state.clone();
                state.connections.fetch_add(1, Ordering::SeqCst);
                let config = Arc::new(server::Config {
                    keys: vec![state.host_key.lock().unwrap().clone()],
                    auth_rejection_time: Duration::ZERO,
                    auth_rejection_time_initial: Some(Duration::ZERO),
                    inactivity_timeout: None,
                    ..Default::default()
                });
                let handler = Handler {
                    state: state.clone(),
                    channels: HashMap::new(),
                };
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, socket, handler).await {
                        state.handles.lock().unwrap().push(session.handle());
                        let _ = session.await;
                    }
                });
            }
        });
        TestServer {
            port,
            state,
            accept_task,
        }
    }

    /// Nombre de connexions TCP acceptées depuis le démarrage.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// Algorithmes des signatures acceptées (`ssh-ed25519`, `rsa-sha2-512`…).
    pub fn auth_algorithms(&self) -> Vec<String> {
        self.state.auth_algorithms.lock().unwrap().clone()
    }

    /// Commandes exec reçues.
    pub fn commands(&self) -> Vec<String> {
        self.state.commands.lock().unwrap().clone()
    }

    pub fn authorize(&self, key: PublicKey) {
        self.state.authorized.lock().unwrap().push(key);
    }

    /// Change la clé d'hôte : les prochaines connexions verront une autre empreinte.
    pub fn rotate_host_key(&self) {
        *self.state.host_key.lock().unwrap() = new_key();
    }

    /// Coupe toutes les sessions en cours (le serveur continue d'écouter).
    pub async fn disconnect_all(&self) {
        let handles: Vec<server::Handle> = self.state.handles.lock().unwrap().drain(..).collect();
        for handle in handles {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "test".into(), "".into())
                .await;
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

struct Handler {
    state: Arc<State>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl Handler {
    fn is_authorized(&self, key: &PublicKey) -> bool {
        self.state
            .authorized
            .lock()
            .unwrap()
            .iter()
            .any(|k| k.key_data() == key.key_data())
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.is_authorized(offer.public_key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if !self.is_authorized(key.public_key) {
            return Ok(Auth::reject());
        }
        self.state
            .auth_algorithms
            .lock()
            .unwrap()
            .push(key.algorithm.to_string());
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.state.allow_direct_tcpip {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        match TcpStream::connect((host_to_connect, port_to_connect as u16)).await {
            Ok(mut tcp) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
                });
            }
            Err(_) => reply.reject(ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        match self.channels.remove(&channel) {
            Some(ch) => {
                session.channel_success(channel)?;
                self.state.commands.lock().unwrap().push(command.clone());
                tokio::spawn(run_command(self.state.clone(), command, ch));
            }
            None => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

/// Lance `sh -c <commande>` et relie ses trois flux au canal SSH.
async fn run_command(state: Arc<State>, command: String, channel: Channel<Msg>) {
    let (mut read_half, write_half) = channel.split();
    let write_half = Arc::new(write_half);
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&command)
        .envs(state.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .env_remove("SSH_AUTH_SOCK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            let _ = write_half
                .extended_data(1, format!("sh: {e}\n").as_bytes())
                .await;
            let _ = write_half.exit_status(126).await;
            let _ = write_half.eof().await;
            let _ = write_half.close().await;
            return;
        }
    };
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    let out_writer = write_half.clone();
    let out_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_writer.data(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let err_writer = write_half.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if err_writer.extended_data(1, &buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    // stdin du processus ; se termine quand le client ferme le canal.
    let mut in_task = tokio::spawn(async move {
        loop {
            match read_half.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if let Some(pipe) = stdin.as_mut() {
                        if pipe.write_all(&data).await.is_err() {
                            stdin = None;
                        }
                    }
                }
                Some(ChannelMsg::Eof) => stdin = None,
                Some(ChannelMsg::Close) | None => return,
                Some(_) => {}
            }
        }
    });

    tokio::select! {
        status = child.wait() => {
            let _ = out_task.await;
            let _ = err_task.await;
            let code = match status {
                Ok(status) => status.code().map(|c| c as u32).unwrap_or(137),
                Err(_) => 126,
            };
            let _ = write_half.exit_status(code).await;
            let _ = write_half.eof().await;
            let _ = write_half.close().await;
            in_task.abort();
        }
        _ = &mut in_task => {
            // Le client a fermé le canal (annulation) : on arrête la commande.
            out_task.abort();
            err_task.abort();
            let _ = child.kill().await;
            let _ = write_half.close().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Environnement complet : bastion + cibles + arborescence + faux sudo
// ---------------------------------------------------------------------------

const FAKE_SUDO: &str = r#"#!/bin/sh
# Faux sudo pour les tests. Le mode est lu dans $LOGANO_SUDO_MODE_FILE :
#   nopasswd          -> exécute la commande sans rien demander
#   password:<secret> -> refuse `-n`, exige `-S` et le bon mot de passe sur stdin
mode=$(cat "$LOGANO_SUDO_MODE_FILE")
nflag=0
sflag=0
while [ $# -gt 0 ]; do
  case "$1" in
    -n) nflag=1; shift ;;
    -S) sflag=1; shift ;;
    -p) shift; shift ;;
    --) shift; break ;;
    -*) echo "sudo: option non prise en charge: $1" >&2; exit 1 ;;
    *) break ;;
  esac
done
case "$mode" in
  nopasswd) ;;
  password:*)
    expected=${mode#password:}
    if [ "$nflag" -eq 1 ]; then
      echo "sudo: a password is required" >&2
      exit 1
    fi
    if [ "$sflag" -eq 0 ]; then
      echo "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper" >&2
      exit 1
    fi
    if ! IFS= read -r given; then
      echo "sudo: no password was provided" >&2
      exit 1
    fi
    if [ "$given" != "$expected" ]; then
      echo "Sorry, try again." >&2
      echo "sudo: 1 incorrect password attempt" >&2
      exit 1
    fi
    ;;
  *) echo "sudo: mode de test inconnu: $mode" >&2; exit 1 ;;
esac
echo "$*" >> "$LOGANO_SUDO_LOG"
exec "$@"
"#;

const FAKE_STAT: &str = r#"#!/bin/sh
# Émulation minimale de `stat -L -c '%s %Y %n' -- fichiers…` (GNU coreutils)
# au-dessus du stat BSD de macOS, qui ne connaît pas `-c`.
fmt=""
while [ $# -gt 0 ]; do
  case "$1" in
    -L) shift ;;
    -c) fmt="$2"; shift; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if [ "$fmt" != "%s %Y %n" ]; then
  echo "stat: format non pris en charge par l'émulation: $fmt" >&2
  exit 2
fi
rc=0
for f in "$@"; do
  if [ -e "$f" ]; then
    /usr/bin/stat -L -f '%z %m %N' "$f"
  else
    echo "stat: cannot statx '$f': No such file or directory" >&2
    rc=1
  fi
done
exit $rc
"#;

const FAKE_CHMOD: &str = r#"#!/bin/sh
# Le chmod BSD de macOS prend `--` placé après le mode pour un nom de fichier ;
# le chmod GNU des serveurs l'accepte. On retire ce `--` et on délègue.
mode="$1"
shift
if [ "$1" = "--" ]; then shift; fi
exec /bin/chmod "$mode" "$@"
"#;

fn write_script(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Vrai si le `stat` du système comprend `-c` (GNU). Faux sur macOS.
fn system_stat_is_gnu() -> bool {
    std::process::Command::new("stat")
        .args(["-c", "%s", "/"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Vrai si `chmod +r -- fichier` fonctionne (GNU). Faux sur macOS.
fn system_chmod_accepts_double_dash(scratch: &Path) -> bool {
    let probe = scratch.join("chmod_probe");
    std::fs::write(&probe, "").unwrap();
    let ok = std::process::Command::new("chmod")
        .args(["+r", "--"])
        .arg(&probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = std::fs::remove_file(&probe);
    ok
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data)
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// Octets pseudo-aléatoires reproductibles (incompressibles : le transfert
/// d'un gros fichier prend ainsi plusieurs paquets même après gzip).
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Droits des fichiers de logs de test : comme `-rw-r-----` vu par un
/// utilisateur qui n'est ni propriétaire ni dans le groupe, c'est-à-dire
/// illisible tant que `sudo chmod +r` n'est pas passé. Le propriétaire étant
/// ici l'utilisateur qui lance les tests, on lui retire son droit de lecture.
pub const UNREADABLE: u32 = 0o240;

pub fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub bastion: TestServer,
    pub target: TestServer,
    pub target2: TestServer,
    pub client_key: PrivateKey,
    pub client_key_path: PathBuf,
    pub syslog_root: PathBuf,
    pub sudo_mode_file: PathBuf,
    pub sudo_log: PathBuf,
}

pub const ERLANG_GATEWAY: &[u8] = b"2026-11-09T00:00:01+01:00 etam-sb-gw01 [info] GET /api/ping\n2026-11-09T00:00:02+01:00 etam-sb-gw01 [info] Sent 200 in 1ms\n";

impl Env {
    pub async fn start() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        // Faux binaires.
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_script(&bin.join("sudo"), FAKE_SUDO);
        if !system_stat_is_gnu() {
            write_script(&bin.join("stat"), FAKE_STAT);
        }
        if !system_chmod_accepts_double_dash(&root) {
            write_script(&bin.join("chmod"), FAKE_CHMOD);
        }
        let sudo_mode_file = root.join("sudo_mode");
        std::fs::write(&sudo_mode_file, "nopasswd").unwrap();
        let sudo_log = root.join("sudo.log");
        std::fs::write(&sudo_log, "").unwrap();
        let command_env = vec![
            (
                "PATH".to_string(),
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", bin.display()),
            ),
            (
                "LOGANO_SUDO_MODE_FILE".to_string(),
                sudo_mode_file.display().to_string(),
            ),
            (
                "LOGANO_SUDO_LOG".to_string(),
                sudo_log.display().to_string(),
            ),
        ];

        // Arborescence de logs.
        let syslog_root = root.join("srv/syslog");
        let apps = syslog_root.join("2026/11/09/APPS");
        let put = |rel: &str, content: &[u8]| {
            let path = apps.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(UNREADABLE)).unwrap();
        };
        put(
            "etam_sb_gateway/etam-sb/erlang.log.gz",
            &gzip(ERLANG_GATEWAY),
        );
        put(
            "etam_sb_gateway/etam-sb/haproxy.log.gz",
            &gzip(&noise(300_000, 7)),
        );
        put("jar_sb_admin/jar-sb-atlas/erlang.log", &plain_log(2_000));
        put(
            "jar_sb_admin/jar-sb-atlas02/erlang.log.gz",
            &gzip(b"atlas02\n"),
        );
        put(
            "riakn/riak-sb/console.log",
            b"2026-11-09 00:00:00.000 [info] <0.1.0> riak ok\n",
        );
        put("riakn/riak-sb/haproxy.log", &noise(24 * 1024 * 1024, 42));
        std::fs::create_dir_all(syslog_root.join("2026/11/09/SYSTEM/host01")).unwrap();

        // Clé du client et serveurs.
        let client_key = new_key();
        let client_key_path = root.join("id_test");
        client_key
            .write_openssh_file(&client_key_path, LineEnding::LF)
            .unwrap();
        let authorized = vec![client_key.public_key().clone()];
        let bastion = TestServer::start(authorized.clone(), command_env.clone(), true).await;
        let target = TestServer::start(authorized.clone(), command_env.clone(), false).await;
        let target2 = TestServer::start(authorized, command_env, false).await;

        Env {
            dir,
            bastion,
            target,
            target2,
            client_key,
            client_key_path,
            syslog_root,
            sudo_mode_file,
            sudo_log,
        }
    }

    pub fn bastion_config(&self, mode: JumpMode) -> BastionConfig {
        let mut bastion = BastionConfig::new("127.0.0.1", "testeur");
        bastion.port = self.bastion.port;
        bastion.auth = AuthConfig::Key {
            identity_file: self.client_key_path.display().to_string(),
        };
        bastion.mode = mode;
        bastion
    }

    fn server_on(&self, id: &str, port: u16) -> ServerConfig {
        let mut server = ServerConfig::new(id, id, "127.0.0.1");
        server.port = port;
        server.path_pattern = format!(
            "{}/{{YYYY}}/{{MM}}/{{DD}}/APPS/{{app_name}}/{{cluster}}/",
            self.syslog_root.display()
        );
        server
    }

    pub fn server(&self) -> ServerConfig {
        self.server_on("etam-sb", self.target.port)
    }

    pub fn server2(&self) -> ServerConfig {
        self.server_on("jar-sb", self.target2.port)
    }

    pub fn pool(&self, mode: JumpMode) -> SessionPool {
        SessionPool::new(self.bastion_config(mode), ConnectOptions::default())
    }

    pub fn set_sudo_mode(&self, mode: &str) {
        std::fs::write(&self.sudo_mode_file, mode).unwrap();
    }

    pub fn sudo_log(&self) -> String {
        std::fs::read_to_string(&self.sudo_log).unwrap()
    }

    /// Chemin réel d'un fichier de l'arborescence du 2026-11-09.
    pub fn log_path(&self, rel: &str) -> PathBuf {
        self.syslog_root.join("2026/11/09/APPS").join(rel)
    }

    /// Contenu d'un fichier de l'arborescence, quels que soient ses droits.
    pub fn read_log(&self, rel: &str) -> Vec<u8> {
        let path = self.log_path(rel);
        let mode = mode_of(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let content = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        content
    }
}

/// Un `erlang.log` en clair de `lines` lignes.
pub fn plain_log(lines: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..lines {
        writeln!(
            out,
            "2026-11-09T10:{:02}:{:02}+01:00 jar-sb-atlas01 [info] requête {i} traitée pour client{}@example.test",
            (i / 60) % 60,
            i % 60,
            i % 17
        )
        .unwrap();
    }
    out
}

/// Port local sur lequel personne n'écoute.
pub async fn closed_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    listener.local_addr().unwrap().port()
}

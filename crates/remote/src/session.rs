//! Sessions SSH : connexion au bastion, rebond vers la cible, exécution de commandes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::{self, Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::config::{
    expand_tilde, AuthConfig, BastionConfig, HostKeyPolicy, JumpMode, ServerConfig,
};
use crate::error::{RemoteError, Result};
use crate::hostkeys::{self, Verdict};
use crate::shell::shell_word;

/// Fenêtre de canal annoncée au serveur : large, pour ne pas brider le débit
/// des gros téléchargements à travers le bastion.
const WINDOW_SIZE: u32 = 16 * 1024 * 1024;
/// Taille maximale d'un paquet de données (plafond du protocole côté `russh`).
const MAX_PACKET_SIZE: u32 = 65535;
/// Au-delà, le stderr d'une commande est tronqué.
const STDERR_CAP: usize = 64 * 1024;

/// Options de connexion fournies par l'appelant.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Fichier JSON des empreintes de clés d'hôte, obligatoire avec
    /// [`HostKeyPolicy::Tofu`].
    pub known_hosts_path: Option<PathBuf>,
    /// Délai maximal pour établir et authentifier une session (20 s par défaut).
    pub connect_timeout: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions {
            known_hosts_path: None,
            connect_timeout: Duration::from_secs(20),
        }
    }
}

/// Secrets et réglages partagés par toutes les connexions d'un pool.
pub(crate) struct Credentials {
    options: ConnectOptions,
    /// Phrases de passe, par `identity_file` tel qu'écrit dans la config.
    passphrases: Mutex<HashMap<String, SecretString>>,
    /// Clés déjà déchiffrées, par chemin étendu.
    keys: Mutex<HashMap<PathBuf, Arc<PrivateKey>>>,
}

impl Credentials {
    pub(crate) fn new(options: ConnectOptions) -> Self {
        Credentials {
            options,
            passphrases: Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn set_passphrase(&self, identity_file: &str, passphrase: Option<SecretString>) {
        let mut map = self.passphrases.lock().unwrap_or_else(|e| e.into_inner());
        match passphrase {
            Some(p) => {
                map.insert(identity_file.to_string(), p);
            }
            None => {
                map.remove(identity_file);
            }
        }
    }

    /// Lit et déchiffre la clé privée ; le résultat est gardé en mémoire.
    fn load_key(&self, identity_file: &str) -> Result<Arc<PrivateKey>> {
        let path = expand_tilde(identity_file);
        if let Some(key) = self
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&path)
        {
            return Ok(key.clone());
        }
        let text = std::fs::read_to_string(&path).map_err(|e| RemoteError::KeyUnreadable {
            identity_file: identity_file.to_string(),
            detail: e.to_string(),
        })?;
        let key = match keys::decode_secret_key(&text, None) {
            Ok(key) => key,
            Err(err) => {
                let encrypted = matches!(err, keys::Error::KeyIsEncrypted)
                    || text.contains("BEGIN ENCRYPTED PRIVATE KEY")
                    || text.contains("Proc-Type: 4,ENCRYPTED");
                if !encrypted {
                    return Err(RemoteError::KeyUnreadable {
                        identity_file: identity_file.to_string(),
                        detail: err.to_string(),
                    });
                }
                let passphrase = self
                    .passphrases
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(identity_file)
                    .cloned();
                let Some(passphrase) = passphrase else {
                    return Err(RemoteError::KeyPassphraseRequired {
                        identity_file: identity_file.to_string(),
                    });
                };
                keys::decode_secret_key(&text, Some(passphrase.expose_secret())).map_err(|_| {
                    RemoteError::KeyPassphraseInvalid {
                        identity_file: identity_file.to_string(),
                    }
                })?
            }
        };
        let key = Arc::new(key);
        self.keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path, key.clone());
        Ok(key)
    }
}

/// Étape de la connexion, pour choisir la bonne variante d'erreur.
#[derive(Clone, Copy)]
enum Hop {
    Bastion,
    Target,
}

fn unreachable(hop: Hop, host: &str, port: u16, detail: impl Into<String>) -> RemoteError {
    match hop {
        Hop::Bastion => RemoteError::BastionUnreachable {
            host: host.to_string(),
            port,
            detail: detail.into(),
        },
        Hop::Target => RemoteError::TargetUnreachable {
            host: host.to_string(),
            port,
            detail: detail.into(),
        },
    }
}

enum HostKeyFailure {
    Changed { expected: String, actual: String },
    Store(String),
}

type HostKeyReport = Arc<Mutex<Option<HostKeyFailure>>>;

/// Gestionnaire d'événements côté client : ne fait que vérifier la clé d'hôte.
pub(crate) struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: Option<PathBuf>,
    report: HostKeyReport,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &keys::PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.policy == HostKeyPolicy::Insecure {
            return Ok(true);
        }
        let Some(path) = self.known_hosts.as_deref() else {
            return Ok(false);
        };
        let key = server_public_key.public_key();
        let actual = key.fingerprint(HashAlg::Sha256).to_string();
        let algorithm = key.algorithm().to_string();
        let failure =
            match hostkeys::check_or_record(path, &self.host, self.port, &algorithm, &actual) {
                Ok(Verdict::Trusted) => return Ok(true),
                Ok(Verdict::Changed { expected }) => HostKeyFailure::Changed { expected, actual },
                Err(e) => HostKeyFailure::Store(format!("{} : {e}", path.display())),
            };
        *self.report.lock().unwrap_or_else(|e| e.into_inner()) = Some(failure);
        Ok(false)
    }
}

fn client_config(keepalive_secs: u64) -> Arc<client::Config> {
    Arc::new(client::Config {
        window_size: WINDOW_SIZE,
        maximum_packet_size: MAX_PACKET_SIZE,
        keepalive_interval: (keepalive_secs > 0).then(|| Duration::from_secs(keepalive_secs)),
        keepalive_max: 3,
        inactivity_timeout: None,
        nodelay: true,
        ..Default::default()
    })
}

fn new_handler(
    host: &str,
    port: u16,
    policy: HostKeyPolicy,
    creds: &Credentials,
) -> Result<(ClientHandler, HostKeyReport)> {
    if policy == HostKeyPolicy::Tofu && creds.options.known_hosts_path.is_none() {
        return Err(RemoteError::invalid_config(
            "host_key_policy = \"tofu\" exige un fichier known_hosts (ConnectOptions::known_hosts_path)",
        ));
    }
    let report: HostKeyReport = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        host: host.to_string(),
        port,
        policy,
        known_hosts: creds.options.known_hosts_path.clone(),
        report: report.clone(),
    };
    Ok((handler, report))
}

/// Traduit un échec d'établissement de session : clé d'hôte d'abord, réseau sinon.
fn handshake_error(
    hop: Hop,
    host: &str,
    port: u16,
    report: &HostKeyReport,
    detail: String,
) -> RemoteError {
    match report.lock().unwrap_or_else(|e| e.into_inner()).take() {
        Some(HostKeyFailure::Changed { expected, actual }) => RemoteError::HostKeyChanged {
            host: host.to_string(),
            port,
            expected,
            actual,
        },
        Some(HostKeyFailure::Store(detail)) => RemoteError::InvalidConfig {
            detail: format!("fichier known_hosts inutilisable ({detail})"),
        },
        None => unreachable(hop, host, port, detail),
    }
}

/// Hachages à essayer pour une clé RSA, du meilleur au moins bon.
async fn rsa_hash_candidates(handle: &Handle<ClientHandler>) -> Vec<Option<HashAlg>> {
    match handle.best_supported_rsa_hash().await {
        // Le serveur a annoncé ses algorithmes : on prend le meilleur.
        Ok(Some(best)) => vec![best],
        // Pas d'annonce : rsa-sha2-512 puis rsa-sha2-256 (jamais ssh-rsa/SHA-1 d'office).
        _ => vec![Some(HashAlg::Sha512), Some(HashAlg::Sha256)],
    }
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    hop: Hop,
    host: &str,
    port: u16,
    user: &str,
    auth: &AuthConfig,
    creds: &Arc<Credentials>,
) -> Result<()> {
    let rejected = || RemoteError::KeyRejected {
        host: host.to_string(),
        user: user.to_string(),
    };
    match auth {
        AuthConfig::Key { identity_file } => {
            let key = {
                let creds = creds.clone();
                let identity_file = identity_file.clone();
                tokio::task::spawn_blocking(move || creds.load_key(&identity_file))
                    .await
                    .map_err(|e| RemoteError::KeyUnreadable {
                        identity_file: "?".into(),
                        detail: e.to_string(),
                    })??
            };
            let candidates = if matches!(key.algorithm(), Algorithm::Rsa { .. }) {
                rsa_hash_candidates(handle).await
            } else {
                vec![None]
            };
            for hash in candidates {
                let result = handle
                    .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key.clone(), hash))
                    .await
                    .map_err(|e| unreachable(hop, host, port, e.to_string()))?;
                if result.success() {
                    return Ok(());
                }
            }
            Err(rejected())
        }
        AuthConfig::Agent => {
            let agent_err = |e: keys::Error| RemoteError::AgentUnavailable {
                detail: e.to_string(),
            };
            let mut agent = AgentClient::connect_env().await.map_err(agent_err)?;
            let identities = agent.request_identities().await.map_err(agent_err)?;
            if identities.is_empty() {
                return Err(RemoteError::AgentUnavailable {
                    detail: "l'agent ne contient aucune clé (ssh-add)".into(),
                });
            }
            for identity in identities {
                let AgentIdentity::PublicKey { key, .. } = identity else {
                    continue;
                };
                let candidates = if matches!(key.algorithm(), Algorithm::Rsa { .. }) {
                    rsa_hash_candidates(handle).await
                } else {
                    vec![None]
                };
                for hash in candidates {
                    // Un refus de signer de l'agent n'empêche pas d'essayer la clé suivante.
                    if let Ok(result) = handle
                        .authenticate_publickey_with(user, key.clone(), hash, &mut agent)
                        .await
                    {
                        if result.success() {
                            return Ok(());
                        }
                    }
                    if handle.is_closed() {
                        return Err(unreachable(
                            hop,
                            host,
                            port,
                            "connexion fermée pendant l'authentification",
                        ));
                    }
                }
            }
            Err(rejected())
        }
    }
}

/// Session ouverte sur un bastion, partagée par les sessions cibles.
pub(crate) struct BastionLink {
    pub(crate) cfg: BastionConfig,
    handle: Handle<ClientHandler>,
}

impl BastionLink {
    pub(crate) fn is_alive(&self) -> bool {
        !self.handle.is_closed()
    }

    pub(crate) async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
    }
}

pub(crate) async fn connect_bastion(
    cfg: &BastionConfig,
    creds: &Arc<Credentials>,
) -> Result<BastionLink> {
    let (handler, report) = new_handler(&cfg.host, cfg.port, cfg.host_key_policy, creds)?;
    let attempt = async {
        let mut handle = client::connect(
            client_config(cfg.keepalive_secs),
            (cfg.host.as_str(), cfg.port),
            handler,
        )
        .await
        .map_err(|e| handshake_error(Hop::Bastion, &cfg.host, cfg.port, &report, e.to_string()))?;
        authenticate(
            &mut handle,
            Hop::Bastion,
            &cfg.host,
            cfg.port,
            &cfg.user,
            &cfg.auth,
            creds,
        )
        .await?;
        Ok(handle)
    };
    let handle = match tokio::time::timeout(creds.options.connect_timeout, attempt).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(unreachable(
                Hop::Bastion,
                &cfg.host,
                cfg.port,
                "délai de connexion dépassé",
            ))
        }
    };
    Ok(BastionLink {
        cfg: cfg.clone(),
        handle,
    })
}

pub(crate) async fn connect_target(
    bastion: Arc<BastionLink>,
    server: &ServerConfig,
    global: &BastionConfig,
    creds: &Arc<Credentials>,
) -> Result<RemoteSession> {
    let host = server.host.as_str();
    let port = server.port;
    let user = server.effective_user(global).to_string();
    let auth = server.effective_auth(global).clone();
    let policy = bastion.cfg.host_key_policy;
    let config = client_config(bastion.cfg.keepalive_secs);
    let (handler, report) = new_handler(host, port, policy, creds)?;

    let attempt = async {
        let mut handle = match bastion.cfg.mode {
            JumpMode::Nc => {
                let command = bastion
                    .cfg
                    .nc_command
                    .replace("{host}", &shell_word(host))
                    .replace("{port}", &port.to_string());
                let channel = bastion.handle.channel_open_session().await.map_err(|e| {
                    unreachable(
                        Hop::Bastion,
                        &bastion.cfg.host,
                        bastion.cfg.port,
                        format!("session bastion perdue ({e})"),
                    )
                })?;
                channel.exec(true, command).await.map_err(|e| {
                    unreachable(
                        Hop::Bastion,
                        &bastion.cfg.host,
                        bastion.cfg.port,
                        e.to_string(),
                    )
                })?;
                let (pipe, diag) = ExecPipe::spawn(channel);
                match client::connect_stream(config, pipe, handler).await {
                    Ok(handle) => handle,
                    Err(e) => {
                        let detail = diag.describe(&e.to_string()).await;
                        return Err(handshake_error(Hop::Target, host, port, &report, detail));
                    }
                }
            }
            JumpMode::DirectTcpip => {
                let channel = match bastion
                    .handle
                    .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
                    .await
                {
                    Ok(channel) => channel,
                    Err(russh::Error::ChannelOpenFailure(reason)) => {
                        return Err(unreachable(
                            Hop::Target,
                            host,
                            port,
                            format!("le bastion n'a pas pu ouvrir la connexion ({reason:?})"),
                        ))
                    }
                    Err(e) => {
                        return Err(unreachable(
                            Hop::Bastion,
                            &bastion.cfg.host,
                            bastion.cfg.port,
                            e.to_string(),
                        ))
                    }
                };
                client::connect_stream(config, channel.into_stream(), handler)
                    .await
                    .map_err(|e| handshake_error(Hop::Target, host, port, &report, e.to_string()))?
            }
        };
        authenticate(&mut handle, Hop::Target, host, port, &user, &auth, creds).await?;
        Ok(handle)
    };
    let handle = match tokio::time::timeout(creds.options.connect_timeout, attempt).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(unreachable(
                Hop::Target,
                host,
                port,
                "délai de connexion dépassé",
            ))
        }
    };
    Ok(RemoteSession {
        server: server.clone(),
        handle,
        _bastion: bastion,
    })
}

// ---------------------------------------------------------------------------
// Transport `nc` : le canal exec du bastion vu comme un flux d'octets.
// ---------------------------------------------------------------------------

/// Ce que `nc` a dit sur le bastion, pour expliquer un échec de connexion.
#[derive(Default)]
struct NcDiag {
    state: Mutex<NcState>,
}

#[derive(Default)]
struct NcState {
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    done: bool,
}

impl NcDiag {
    /// Attend brièvement la fin de `nc`, puis rend son stderr ou son statut.
    async fn describe(&self, fallback: &str) -> String {
        for _ in 0..25 {
            if self.state.lock().unwrap_or_else(|e| e.into_inner()).done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stderr = String::from_utf8_lossy(&state.stderr).trim().to_string();
        match (stderr.is_empty(), state.exit_status) {
            (false, _) => stderr,
            (true, Some(127)) => "commande nc introuvable sur le bastion (statut 127)".to_string(),
            (true, Some(code)) => format!(
                "nc s'est terminé sur le bastion avec le statut {code} (hôte ou port injoignable depuis le bastion ?)"
            ),
            (true, None) => fallback.to_string(),
        }
    }
}

/// Flux `AsyncRead + AsyncWrite` au-dessus d'un canal exec. Contrairement à
/// `Channel::into_stream`, garde le stderr et le statut de sortie de la
/// commande, ce qui permet de dire pourquoi `nc` a échoué.
struct ExecPipe {
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
    writer: Pin<Box<dyn AsyncWrite + Send>>,
    write_half: Option<ChannelWriteHalf<client::Msg>>,
}

impl ExecPipe {
    fn spawn(channel: Channel<client::Msg>) -> (Self, Arc<NcDiag>) {
        let (read_half, write_half) = channel.split();
        let writer: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(write_half.make_writer());
        let (tx, rx) = mpsc::channel(64);
        let diag = Arc::new(NcDiag::default());
        tokio::spawn(pump(read_half, tx, diag.clone()));
        let pipe = ExecPipe {
            rx,
            current: Vec::new(),
            pos: 0,
            writer,
            write_half: Some(write_half),
        };
        (pipe, diag)
    }
}

async fn pump(mut read_half: ChannelReadHalf, tx: mpsc::Sender<Vec<u8>>, diag: Arc<NcDiag>) {
    while let Some(msg) = read_half.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                if tx.send(data.to_vec()).await.is_err() {
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                let mut state = diag.state.lock().unwrap_or_else(|e| e.into_inner());
                let room = 8192usize.saturating_sub(state.stderr.len());
                state
                    .stderr
                    .extend_from_slice(&data[..data.len().min(room)]);
            }
            ChannelMsg::ExitStatus { exit_status } => {
                diag.state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .exit_status = Some(exit_status);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    diag.state.lock().unwrap_or_else(|e| e.into_inner()).done = true;
}

impl AsyncRead for ExecPipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.pos < this.current.len() {
                let n = (this.current.len() - this.pos).min(buf.remaining());
                buf.put_slice(&this.current[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.current = chunk;
                    this.pos = 0;
                }
                // Fin de flux : `nc` s'est arrêté.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for ExecPipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writer.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_shutdown(cx)
    }
}

impl Drop for ExecPipe {
    fn drop(&mut self) {
        // La session cible est terminée : on ferme le canal pour que `nc` s'arrête.
        close_in_background(self.write_half.take());
    }
}

fn close_in_background(write_half: Option<ChannelWriteHalf<client::Msg>>) {
    if let (Some(write_half), Ok(runtime)) = (write_half, tokio::runtime::Handle::try_current()) {
        runtime.spawn(async move {
            let _ = write_half.close().await;
        });
    }
}

// ---------------------------------------------------------------------------
// Session cible et exécution de commandes.
// ---------------------------------------------------------------------------

/// Résultat d'une commande distante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `None` si la commande a été tuée par un signal.
    pub exit_status: Option<u32>,
}

impl ExecOutput {
    /// Vrai si la commande s'est terminée avec le statut 0.
    pub fn success(&self) -> bool {
        self.exit_status == Some(0)
    }

    /// stdout décodé en UTF-8 (caractères invalides remplacés).
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// stderr décodé en UTF-8, sans blancs de début ni de fin.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Session SSH authentifiée sur un serveur cible, à travers le bastion.
/// Plusieurs commandes peuvent tourner en parallèle (un canal chacune).
pub struct RemoteSession {
    server: ServerConfig,
    handle: Handle<ClientHandler>,
    /// Garde la session bastion en vie tant que la session cible existe.
    _bastion: Arc<BastionLink>,
}

impl std::fmt::Debug for RemoteSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSession")
            .field("server", &self.server.id)
            .field("host", &self.server.host)
            .finish()
    }
}

impl RemoteSession {
    /// Configuration du serveur de cette session.
    pub fn server(&self) -> &ServerConfig {
        &self.server
    }

    /// Faux dès que la session est fermée ou perdue.
    pub fn is_alive(&self) -> bool {
        !self.handle.is_closed()
    }

    /// Ferme la session proprement.
    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
    }

    pub(crate) fn label(&self) -> String {
        self.server.host.clone()
    }

    fn lost(&self, e: russh::Error) -> RemoteError {
        RemoteError::SessionLost {
            server: self.label(),
            detail: e.to_string(),
        }
    }

    async fn open_exec(&self, command: &str, stdin: Option<&[u8]>) -> Result<Channel<client::Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| self.lost(e))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| self.lost(e))?;
        if let Some(data) = stdin.filter(|d| !d.is_empty()) {
            channel.data(data).await.map_err(|e| self.lost(e))?;
        }
        // stdin fermé d'emblée : aucune commande ne reste bloquée à attendre une saisie.
        channel.eof().await.map_err(|e| self.lost(e))?;
        Ok(channel)
    }

    /// Exécute `command` (interprétée par le shell distant) et rend sa sortie
    /// complète. Un statut non nul n'est pas une erreur : il est dans
    /// [`ExecOutput::exit_status`].
    pub async fn exec(&self, command: &str) -> Result<ExecOutput> {
        self.exec_with_stdin(command, None).await
    }

    /// Comme [`exec`](Self::exec), en envoyant d'abord `stdin` à la commande
    /// (utilisé pour `sudo -S`). Le contenu de `stdin` n'est jamais journalisé.
    pub async fn exec_with_stdin(&self, command: &str, stdin: Option<&[u8]>) -> Result<ExecOutput> {
        let mut stream = ExecStream::new(self.open_exec(command, stdin).await?, self.label());
        let mut stdout = Vec::new();
        while let Some(chunk) = stream.next_chunk().await? {
            stdout.extend_from_slice(&chunk);
        }
        if stream.exit_status.is_none() && stream.signal.is_none() && !self.is_alive() {
            return Err(RemoteError::SessionLost {
                server: self.label(),
                detail: "connexion fermée pendant l'exécution".into(),
            });
        }
        Ok(ExecOutput {
            stdout,
            stderr: std::mem::take(&mut stream.stderr),
            exit_status: stream.exit_status,
        })
    }

    /// Lance `command` et rend son stdout au fil de l'eau (pour les
    /// téléchargements). La mémoire reste bornée : tant que l'appelant ne lit
    /// pas, le serveur est ralenti par le contrôle de flux.
    pub async fn exec_stream(&self, command: &str) -> Result<ExecStream> {
        Ok(ExecStream::new(
            self.open_exec(command, None).await?,
            self.label(),
        ))
    }
}

/// Sortie d'une commande distante lue morceau par morceau.
pub struct ExecStream {
    channel: Option<Channel<client::Msg>>,
    server: String,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    signal: Option<String>,
}

impl ExecStream {
    fn new(channel: Channel<client::Msg>, server: String) -> Self {
        ExecStream {
            channel: Some(channel),
            server,
            stderr: Vec::new(),
            exit_status: None,
            signal: None,
        }
    }

    /// Prochain morceau de stdout, ou `None` quand la commande est terminée
    /// (le statut de sortie et le stderr sont alors disponibles).
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let Some(channel) = self.channel.as_mut() else {
                return Ok(None);
            };
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => return Ok(Some(data.to_vec())),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    let room = STDERR_CAP.saturating_sub(self.stderr.len());
                    self.stderr.extend_from_slice(&data[..data.len().min(room)]);
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    self.exit_status = Some(exit_status);
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    self.signal = Some(format!("{signal_name:?}"));
                }
                Some(ChannelMsg::Failure) => {
                    self.channel = None;
                    return Err(RemoteError::CommandFailed {
                        server: self.server.clone(),
                        exit_status: None,
                        stderr: "le serveur a refusé d'exécuter la commande".into(),
                    });
                }
                Some(ChannelMsg::Close) | None => {
                    self.channel = None;
                    return Ok(None);
                }
                Some(_) => {}
            }
        }
    }

    /// Statut de sortie, connu une fois le flux terminé. `None` si la commande
    /// a été tuée par un signal ou si la connexion a été coupée.
    pub fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    /// Signal qui a tué la commande, le cas échéant.
    pub fn signal(&self) -> Option<&str> {
        self.signal.as_deref()
    }

    /// stderr reçu jusqu'ici (tronqué à 64 Kio).
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// stderr décodé, sans blancs de début ni de fin.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }

    /// Ferme le canal sans attendre la fin : la commande distante est interrompue.
    pub async fn close(mut self) {
        if let Some(channel) = self.channel.take() {
            let _ = channel.close().await;
        }
    }
}

impl Drop for ExecStream {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.take() {
            let (_, write_half) = channel.split();
            close_in_background(Some(write_half));
        }
    }
}

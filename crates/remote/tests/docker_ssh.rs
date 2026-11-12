//! Tests d'intégration contre les deux conteneurs `sshd` de `docker/`
//! (bastion avec `nc`, cible avec l'arborescence et sudo).
//!
//! Désactivés par défaut. Voir l'en-tête de `docker/docker-compose.yml` :
//!
//! ```text
//! ./docker/gen-keys.sh
//! docker compose -f docker/docker-compose.yml up -d --build
//! cargo test -p logano-remote --features docker-tests --test docker_ssh
//! ```
#![cfg(feature = "docker-tests")]

use std::io::Read as _;
use std::path::PathBuf;

use chrono::NaiveDate;
use logano_remote::{
    AppInfo, AuthConfig, BastionConfig, CancellationToken, ConnectOptions, HostKeyPolicy, JumpMode,
    LogKind, RemoteError, RemoteSession, SecretString, ServerConfig, SessionPool,
};

const TARGET_HOST: &str = "syslogserver01.priv.testadm-sb.kbrw.test";
const SUDO_PASSWORD: &str = "logano-sudo-pw";

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 11, 9).unwrap()
}

fn key_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docker/keys/id_test")
        .display()
        .to_string()
}

fn bastion(mode: JumpMode) -> BastionConfig {
    let mut bastion = BastionConfig::new("127.0.0.1", "jump");
    bastion.port = std::env::var("LOGANO_DOCKER_BASTION_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    bastion.auth = AuthConfig::Key {
        identity_file: key_path(),
    };
    bastion.mode = mode;
    bastion
}

/// Serveur cible vu par l'utilisateur `user` (`logs` ou `logspw`).
fn server(user: &str) -> ServerConfig {
    let mut server = ServerConfig::new(format!("test-sb-{user}"), "Test — sandbox", TARGET_HOST);
    server.user = Some(user.to_string());
    server
}

fn pool(mode: JumpMode) -> SessionPool {
    SessionPool::new(bastion(mode), ConnectOptions::default())
}

fn gunzip(path: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// Remet les fichiers en `-rw-r-----` (les tests précédents ont pu les ouvrir).
async fn reset_permissions(pool: &SessionPool) {
    let session = pool.session(&server("logs")).await.unwrap();
    let out = session
        .exec("sudo -n find /srv/syslog -type f -exec chmod 640 {} +")
        .await
        .unwrap();
    assert!(out.success(), "{}", out.stderr_text());
}

async fn file_of(session: &RemoteSession, app: &str, cluster: &str) -> logano_remote::RemoteFile {
    session
        .list_files(day(), app, cluster)
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.kind == LogKind::Erlang)
        .expect("erlang.log présent")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nc_decouverte_sudo_sans_mot_de_passe_et_telechargements() {
    let pool = pool(JumpMode::Nc);
    reset_permissions(&pool).await;
    let session = pool.session(&server("logs")).await.unwrap();

    let apps = session.discover_apps(day()).await.unwrap();
    assert_eq!(
        apps,
        vec![
            AppInfo {
                name: "etam_sb_gateway".into(),
                clusters: vec!["etam-sb".into()]
            },
            AppInfo {
                name: "jar_sb_admin".into(),
                clusters: vec!["jar-sb-atlas".into(), "jar-sb-atlas02".into()]
            },
        ]
    );
    assert!(matches!(
        session
            .discover_apps(NaiveDate::from_ymd_opt(2026, 11, 8).unwrap())
            .await,
        Err(RemoteError::DayNotFound { .. })
    ));

    let files = session
        .list_files(day(), "etam_sb_gateway", "etam-sb")
        .await
        .unwrap();
    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .all(|f| f.compressed && f.size > 0 && f.mtime > 0));

    // Sans chmod, le fichier est illisible pour `logs`.
    let gz = file_of(&session, "etam_sb_gateway", "etam-sb").await;
    let out = session
        .exec(&format!(
            "cat -- {} >/dev/null",
            logano_remote::shell_quote(&gz.path)
        ))
        .await
        .unwrap();
    assert!(!out.success(), "le fichier devrait être en -rw-r-----");

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("erlang.log.gz");
    let outcome = session
        .download(&gz, &dest, None, |_| {}, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(outcome.bytes, gz.size);
    assert_eq!(gunzip(&dest), b"gateway ligne 1\ngateway ligne 2\n");

    let plain = file_of(&session, "jar_sb_admin", "jar-sb-atlas").await;
    assert!(!plain.compressed);
    let dest = dir.path().join("atlas.log.gz");
    session
        .download(&plain, &dest, None, |_| {}, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        gunzip(&dest),
        b"atlas ligne 1\natlas ligne 2\natlas ligne 3\n"
    );
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sudo_avec_mot_de_passe() {
    let pool = pool(JumpMode::Nc);
    reset_permissions(&pool).await;
    let session = pool.session(&server("logspw")).await.unwrap();
    let file = file_of(&session, "jar_sb_admin", "jar-sb-atlas02").await;
    let paths = [file.path.clone()];

    assert!(matches!(
        session.ensure_readable(&paths, None).await,
        Err(RemoteError::SudoPasswordRequired { .. })
    ));

    let wrong = SecretString::from("pas-le-bon".to_string());
    let err = session
        .ensure_readable(&paths, Some(&wrong))
        .await
        .unwrap_err();
    assert!(matches!(err, RemoteError::SudoDenied { .. }), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("pas-le-bon"));

    let password = SecretString::from(SUDO_PASSWORD.to_string());
    session
        .ensure_readable(&paths, Some(&password))
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("atlas02.log.gz");
    session
        .download(
            &file,
            &dest,
            Some(&password),
            |_| {},
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(gunzip(&dest), b"atlas02\n");
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_tcpip_et_reutilisation_du_bastion() {
    let pool = pool(JumpMode::DirectTcpip);
    let a = pool.session(&server("logs")).await.unwrap();
    let b = pool.session(&server("logspw")).await.unwrap();
    assert_eq!(a.discover_apps(day()).await.unwrap().len(), 2);
    assert_eq!(b.discover_apps(day()).await.unwrap().len(), 2);
    let stats = pool.stats();
    assert_eq!(
        (stats.bastion_connections, stats.target_connections),
        (1, 2)
    );
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erreurs_de_connexion() {
    // Hôte inconnu du bastion : nc échoue.
    let pool = pool(JumpMode::Nc);
    let mut unknown = server("logs");
    unknown.host = "serveur-inexistant.kbrw.test".into();
    assert!(matches!(
        pool.session(&unknown).await,
        Err(RemoteError::TargetUnreachable { .. })
    ));

    // Utilisateur inconnu sur la cible : clé refusée.
    assert!(matches!(
        pool.session(&server("personne")).await,
        Err(RemoteError::KeyRejected { .. })
    ));

    // TOFU : premier contact accepté, puis toujours accepté.
    let dir = tempfile::tempdir().unwrap();
    let options = ConnectOptions {
        known_hosts_path: Some(dir.path().join("known_hosts.json")),
        ..Default::default()
    };
    let mut tofu = bastion(JumpMode::Nc);
    tofu.host_key_policy = HostKeyPolicy::Tofu;
    for _ in 0..2 {
        let pool = SessionPool::new(tofu.clone(), options.clone());
        pool.session(&server("logs")).await.unwrap();
        pool.close().await;
    }
}

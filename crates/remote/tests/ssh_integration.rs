//! Tests d'intégration hermétiques : un « bastion » et des « cibles » SSH en
//! processus, sans Docker. Le mode `nc` lance le vrai `nc` de la machine
//! depuis le canal exec du bastion.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::NaiveDate;
use common::{bounded, closed_port, day, gunzip, mode_of, Env, ERLANG_GATEWAY, UNREADABLE};
use logano_remote::{
    AppInfo, AuthConfig, CacheLookup, CancellationToken, Compression, ConnectOptions,
    HostKeyPolicy, JumpMode, LogKind, RawCache, RemoteError, RemoteFile, SecretString, SessionPool,
    StaleReason,
};

fn secret(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn app(name: &str, clusters: &[&str]) -> AppInfo {
    AppInfo {
        name: name.to_string(),
        clusters: clusters.iter().map(|c| c.to_string()).collect(),
    }
}

async fn file_of(
    session: &logano_remote::RemoteSession,
    app: &str,
    cluster: &str,
    kind: LogKind,
) -> RemoteFile {
    session
        .list_files(day(), app, cluster)
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.kind == kind)
        .unwrap_or_else(|| panic!("{kind:?} absent de {app}/{cluster}"))
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_rend_stdout_stderr_statut_et_accepte_stdin() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();

        let out = session
            .exec("printf sortie; printf erreur >&2; exit 7")
            .await
            .unwrap();
        assert_eq!(out.stdout, b"sortie");
        assert_eq!(out.stderr, b"erreur");
        assert_eq!(out.exit_status, Some(7));
        assert!(!out.success());

        let out = session
            .exec_with_stdin("cat", Some(b"bonjour\n"))
            .await
            .unwrap();
        assert_eq!(out.stdout, b"bonjour\n");
        assert!(out.success());

        // Sans stdin, une commande qui lit l'entrée ne reste pas bloquée.
        let out = session.exec("cat; echo fin").await.unwrap();
        assert_eq!(out.stdout, b"fin\n");

        // Le quotage protège apostrophes, espaces, `$`, `;` et retours à la ligne.
        let nasty = "l'app $HOME; rm -rf / \"x\" `id`\nfin";
        let out = session
            .exec(&format!("printf %s {}", logano_remote::shell_quote(nasty)))
            .await
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), nasty);

        // Plusieurs commandes en parallèle sur la même session.
        let (a, b, c) = tokio::join!(
            session.exec("echo a"),
            session.exec("echo b"),
            session.exec("echo c")
        );
        assert_eq!(a.unwrap().stdout, b"a\n");
        assert_eq!(b.unwrap().stdout, b"b\n");
        assert_eq!(c.unwrap().stdout, b"c\n");
        pool.close().await;
    })
    .await;
}

// ---------------------------------------------------------------------------
// Découverte
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decouverte_des_apps_et_clusters() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let commands_before = env.target.commands().len();

        let apps = session.discover_apps(day()).await.unwrap();
        assert_eq!(
            apps,
            vec![
                app("etam_sb_gateway", &["etam-sb"]),
                app("jar_sb_admin", &["jar-sb-atlas", "jar-sb-atlas02"]),
                app("riakn", &["riak-sb"]),
            ]
        );
        // Un seul aller-retour, et le dossier frère SYSTEM est ignoré.
        assert_eq!(env.target.commands().len(), commands_before + 1);
        // Le transport est bien `nc` exécuté sur le bastion.
        assert_eq!(
            env.bastion.commands(),
            vec![format!("nc 127.0.0.1 {}", env.target.port)]
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jour_absent() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let missing = NaiveDate::from_ymd_opt(2026, 11, 8).unwrap();
        match session.discover_apps(missing).await {
            Err(RemoteError::DayNotFound { day, path, .. }) => {
                assert_eq!(day, missing);
                assert!(path.ends_with("/2026/11/08/APPS"), "{path}");
            }
            other => panic!("attendu DayNotFound, obtenu {other:?}"),
        }
        // La session reste utilisable après l'erreur.
        assert_eq!(session.discover_apps(day()).await.unwrap().len(), 3);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn liste_des_fichiers_avec_tailles() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();

        let files = session
            .list_files(day(), "etam_sb_gateway", "etam-sb")
            .await
            .unwrap();
        assert_eq!(files.len(), 2);
        for (file, name, kind) in [
            (&files[0], "erlang.log.gz", LogKind::Erlang),
            (&files[1], "haproxy.log.gz", LogKind::Haproxy),
        ] {
            let local = env.log_path(&format!("etam_sb_gateway/etam-sb/{name}"));
            let meta = std::fs::metadata(&local).unwrap();
            assert_eq!(file.path, local.display().to_string());
            assert_eq!(file.kind, kind);
            assert!(file.compressed);
            assert_eq!(file.size, meta.len());
            let mtime = meta
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            assert_eq!(file.mtime, mtime);
        }

        // Le stat ne demande aucun droit de lecture : les fichiers sont restés fermés.
        assert_eq!(
            mode_of(&env.log_path("etam_sb_gateway/etam-sb/erlang.log.gz")),
            UNREADABLE
        );

        let files = session
            .list_files(day(), "jar_sb_admin", "jar-sb-atlas")
            .await
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].kind, LogKind::Erlang);
        assert!(!files[0].compressed);
        assert_eq!(files[0].size, common::plain_log(2_000).len() as u64);

        let files = session.list_files(day(), "riakn", "riak-sb").await.unwrap();
        let kinds: Vec<(LogKind, bool)> = files.iter().map(|f| (f.kind, f.compressed)).collect();
        assert_eq!(
            kinds,
            vec![(LogKind::Haproxy, false), (LogKind::Console, false)]
        );
        assert_eq!(files[0].size, 24 * 1024 * 1024);

        assert!(matches!(
            session.list_files(day(), "riakn", "inconnu").await,
            Err(RemoteError::FileNotFound { .. })
        ));
        assert!(matches!(
            session.list_files(day(), "..", "etam-sb").await,
            Err(RemoteError::InvalidConfig { .. })
        ));
    })
    .await;
}

// ---------------------------------------------------------------------------
// sudo chmod
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sudo_sans_mot_de_passe() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let a = env.log_path("etam_sb_gateway/etam-sb/erlang.log.gz");
        let b = env.log_path("etam_sb_gateway/etam-sb/haproxy.log.gz");
        assert_eq!(mode_of(&a), UNREADABLE);
        assert!(
            std::fs::read(&a).is_err(),
            "le fichier doit être illisible avant le chmod"
        );

        session
            .ensure_readable(&[a.display().to_string(), b.display().to_string()], None)
            .await
            .unwrap();

        assert_eq!(mode_of(&a) & 0o444, 0o444);
        assert_eq!(mode_of(&b) & 0o444, 0o444);
        assert!(std::fs::read(&a).is_ok());
        let log = env.sudo_log();
        assert_eq!(log.lines().count(), 1, "un seul sudo pour le lot : {log}");
        assert!(
            log.contains(&format!("chmod +r -- {} {}", a.display(), b.display())),
            "{log}"
        );

        // Fichier inexistant : erreur typée.
        let missing = env
            .log_path("etam_sb_gateway/etam-sb/console.log")
            .display()
            .to_string();
        match session
            .ensure_readable(std::slice::from_ref(&missing), None)
            .await
        {
            Err(RemoteError::FileNotFound { path, .. }) => assert_eq!(path, missing),
            other => panic!("attendu FileNotFound, obtenu {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sudo_mot_de_passe_requis_puis_fourni() {
    bounded(async {
        let env = Env::start().await;
        env.set_sudo_mode("password:s3cret d'essai");
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let path = env.log_path("jar_sb_admin/jar-sb-atlas/erlang.log");
        let paths = [path.display().to_string()];

        match session.ensure_readable(&paths, None).await {
            Err(e @ RemoteError::SudoPasswordRequired { .. }) => {
                assert_eq!(e.code(), "sudo_password_required")
            }
            other => panic!("attendu SudoPasswordRequired, obtenu {other:?}"),
        }
        assert_eq!(mode_of(&path), UNREADABLE);

        session
            .ensure_readable(&paths, Some(&secret("s3cret d'essai")))
            .await
            .unwrap();
        assert_eq!(mode_of(&path) & 0o444, 0o444);

        // Le mot de passe n'apparaît ni dans les arguments de sudo ni dans les
        // commandes envoyées au serveur : il ne passe que par stdin.
        assert!(!env.sudo_log().contains("s3cret"));
        assert!(env.target.commands().iter().all(|c| !c.contains("s3cret")));
        assert!(env
            .target
            .commands()
            .iter()
            .any(|c| c.contains("sudo -S -p '' chmod +r -- ")));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sudo_mauvais_mot_de_passe() {
    bounded(async {
        let env = Env::start().await;
        env.set_sudo_mode("password:le-bon");
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let path = env.log_path("jar_sb_admin/jar-sb-atlas/erlang.log");

        let err = session
            .ensure_readable(&[path.display().to_string()], Some(&secret("le-mauvais")))
            .await
            .unwrap_err();
        match &err {
            RemoteError::SudoDenied { stderr, .. } => {
                assert!(stderr.contains("incorrect password attempt"), "{stderr}");
            }
            other => panic!("attendu SudoDenied, obtenu {other:?}"),
        }
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains("le-mauvais"),
            "le mot de passe a fuité : {shown}"
        );
        assert_eq!(mode_of(&path), UNREADABLE);
        assert_eq!(env.sudo_log(), "", "aucune commande ne doit avoir tourné");
    })
    .await;
}

// ---------------------------------------------------------------------------
// Téléchargement
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telechargement_d_un_gz_octets_identiques() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let file = file_of(&session, "etam_sb_gateway", "etam-sb", LogKind::Haproxy).await;
        let dest = env.dir.path().join("out/sous/haproxy.log.gz");

        let last = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let (last2, calls2) = (last.clone(), calls.clone());
        let outcome = session
            .download(
                &file,
                &dest,
                None,
                move |received| {
                    let previous = last2.swap(received, Ordering::SeqCst);
                    assert!(received > previous, "la progression doit croître");
                    calls2.fetch_add(1, Ordering::SeqCst);
                },
                CancellationToken::new(),
            )
            .await
            .unwrap();

        let original = env.read_log("etam_sb_gateway/etam-sb/haproxy.log.gz");
        assert_eq!(std::fs::read(&dest).unwrap(), original, "octets identiques");
        assert_eq!(outcome.bytes, original.len() as u64);
        assert_eq!(outcome.compressed_as, Compression::Gzip);
        assert_eq!(last.load(Ordering::SeqCst), outcome.bytes);
        assert!(
            calls.load(Ordering::SeqCst) > 1,
            "plusieurs morceaux attendus"
        );
        assert!(!dest.with_extension("gz.part").exists());
        // Le chmod a bien été fait avant la lecture.
        assert!(env
            .sudo_log()
            .contains(&format!("chmod +r -- {}", file.path)));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telechargement_d_un_log_en_clair_compresse_a_la_volee() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let file = file_of(&session, "jar_sb_admin", "jar-sb-atlas", LogKind::Erlang).await;
        assert!(!file.compressed);
        let original = common::plain_log(2_000);

        // Le fichier du jour grossit entre le stat et la lecture.
        let remote = env.log_path("jar_sb_admin/jar-sb-atlas/erlang.log");
        std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut grown = original.clone();
        grown.extend_from_slice(b"ligne arrivee apres le stat\n");
        std::fs::write(&remote, &grown).unwrap();
        std::fs::set_permissions(&remote, std::fs::Permissions::from_mode(UNREADABLE)).unwrap();

        let dest = env.dir.path().join("out/erlang.log.gz");
        let outcome = session
            .download(&file, &dest, None, |_| {}, CancellationToken::new())
            .await
            .unwrap();

        let local = std::fs::read(&dest).unwrap();
        assert_eq!(outcome.bytes, local.len() as u64);
        assert!(
            (local.len() as u64) < file.size,
            "le transfert doit être compressé"
        );
        assert_eq!(&local[..2], &[0x1f, 0x8b], "le fichier local est un gzip");
        assert_eq!(
            gunzip(&local),
            original,
            "contenu d'origine, figé à la taille du stat"
        );
        assert!(env
            .target
            .commands()
            .iter()
            .any(|c| c.contains("| gzip -c")));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gros_fichier_au_dela_de_la_fenetre_de_canal() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        // 24 Mio incompressibles : plus que la fenêtre de 16 Mio, donc le
        // contrôle de flux des deux sessions imbriquées est sollicité.
        let file = file_of(&session, "riakn", "riak-sb", LogKind::Haproxy).await;
        let dest = env.dir.path().join("out/haproxy.log.gz");
        let started = std::time::Instant::now();
        let outcome = session
            .download(&file, &dest, None, |_| {}, CancellationToken::new())
            .await
            .unwrap();
        println!(
            "24 Mio via nc : {} octets en {:?}",
            outcome.bytes,
            started.elapsed()
        );
        assert!(
            outcome.bytes > 24 * 1024 * 1024,
            "des données aléatoires ne se compressent pas"
        );
        let original = env.read_log("riakn/riak-sb/haproxy.log");
        assert!(
            gunzip(&std::fs::read(&dest).unwrap()) == original,
            "contenu identique"
        );
    })
    .await;
}

/// Plusieurs fichiers à la fois sur la même session : un canal par téléchargement, sans
/// mélange d'octets entre eux.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telechargements_simultanes_sur_une_session() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let big = file_of(&session, "riakn", "riak-sb", LogKind::Haproxy).await;
        let gz = file_of(&session, "etam_sb_gateway", "etam-sb", LogKind::Haproxy).await;
        let plain = file_of(&session, "jar_sb_admin", "jar-sb-atlas", LogKind::Erlang).await;
        let out = env.dir.path().join("out");
        let fetch = |file: &RemoteFile, name: &str| {
            let (session, file, dest) = (session.clone(), file.clone(), out.join(name));
            async move {
                session
                    .download(&file, &dest, None, |_| {}, CancellationToken::new())
                    .await
                    .unwrap();
                std::fs::read(&dest).unwrap()
            }
        };
        let (a, b, c, d) = tokio::join!(
            fetch(&big, "big.gz"),
            fetch(&gz, "gz.gz"),
            fetch(&plain, "plain.gz"),
            fetch(&big, "big-bis.gz")
        );
        let original = env.read_log("riakn/riak-sb/haproxy.log");
        assert!(gunzip(&a) == original, "gros fichier identique");
        assert!(gunzip(&d) == original, "second exemplaire identique");
        assert!(b == env.read_log("etam_sb_gateway/etam-sb/haproxy.log.gz"), "gz identique");
        assert!(gunzip(&c) == common::plain_log(2_000), "log en clair identique");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn annulation_en_cours_de_telechargement() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        // 24 Mio incompressibles : le transfert est forcément en cours quand on annule.
        let file = file_of(&session, "riakn", "riak-sb", LogKind::Haproxy).await;
        let dest = env.dir.path().join("out/haproxy.log.gz");
        let part = env.dir.path().join("out/haproxy.log.gz.part");

        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let seen = Arc::new(AtomicU64::new(0));
        let seen2 = seen.clone();
        let part2 = part.clone();
        let result = session
            .download(
                &file,
                &dest,
                None,
                move |received| {
                    seen2.store(received, Ordering::SeqCst);
                    if received >= 256 * 1024 {
                        assert!(part2.exists(), "le .part existe pendant le transfert");
                        trigger.cancel();
                    }
                },
                cancel,
            )
            .await;

        assert!(matches!(result, Err(RemoteError::Cancelled)), "{result:?}");
        let received = seen.load(Ordering::SeqCst);
        assert!(
            received >= 256 * 1024 && received < file.size,
            "annulé en cours : {received}"
        );
        assert!(!dest.exists(), "pas de fichier final");
        assert!(!part.exists(), "pas de .part");

        // Un jeton déjà annulé ne lance rien.
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let commands = env.target.commands().len();
        assert!(matches!(
            session
                .download(&file, &dest, None, |_| {}, cancelled)
                .await,
            Err(RemoteError::Cancelled)
        ));
        assert_eq!(env.target.commands().len(), commands);

        // La session reste utilisable.
        assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn telechargement_en_echec_ne_laisse_aucun_fichier() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let dest = env.dir.path().join("out/erlang.log.gz");
        let part = env.dir.path().join("out/erlang.log.gz.part");
        let good = file_of(&session, "etam_sb_gateway", "etam-sb", LogKind::Erlang).await;

        // Fichier distant disparu entre la liste et le téléchargement.
        let mut missing = good.clone();
        missing.path = env
            .log_path("etam_sb_gateway/etam-sb/console.log.gz")
            .display()
            .to_string();
        let result = session
            .download(&missing, &dest, None, |_| {}, CancellationToken::new())
            .await;
        assert!(
            matches!(result, Err(RemoteError::FileNotFound { .. })),
            "{result:?}"
        );
        assert!(!dest.exists() && !part.exists());

        // Taille reçue différente de la taille annoncée : flux considéré coupé.
        let mut truncated = good.clone();
        truncated.size += 10;
        let result = session
            .download(&truncated, &dest, None, |_| {}, CancellationToken::new())
            .await;
        assert!(
            matches!(result, Err(RemoteError::TransferInterrupted { .. })),
            "{result:?}"
        );
        assert!(!dest.exists() && !part.exists());

        // La commande distante sort en erreur (ici : le chemin est un dossier),
        // pour un `.gz` (`cat`) comme pour un `.log` (`head | gzip`).
        let trap = env.log_path("etam_sb_gateway/etam-sb/piege");
        std::fs::create_dir(&trap).unwrap();
        for compressed in [true, false] {
            let mut bad = good.clone();
            bad.path = trap.display().to_string();
            bad.compressed = compressed;
            let result = session
                .download(&bad, &dest, None, |_| {}, CancellationToken::new())
                .await;
            match &result {
                Err(RemoteError::TransferInterrupted { detail, .. }) => {
                    println!("compressed={compressed} : {detail}")
                }
                other => panic!("attendu TransferInterrupted, obtenu {other:?}"),
            }
            assert!(!dest.exists() && !part.exists());
        }

        // sudo exige un mot de passe : rien n'est téléchargé.
        env.set_sudo_mode("password:x");
        let other = file_of(&session, "jar_sb_admin", "jar-sb-atlas02", LogKind::Erlang).await;
        let result = session
            .download(&other, &dest, None, |_| {}, CancellationToken::new())
            .await;
        assert!(
            matches!(result, Err(RemoteError::SudoPasswordRequired { .. })),
            "{result:?}"
        );
        assert!(!dest.exists() && !part.exists());
        // Avec le mot de passe, le même appel aboutit.
        session
            .download(
                &other,
                &dest,
                Some(&secret("x")),
                |_| {},
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(gunzip(&std::fs::read(&dest).unwrap()), b"atlas02\n");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_coupee_pendant_un_telechargement() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let file = file_of(&session, "riakn", "riak-sb", LogKind::Haproxy).await;
        let dest = env.dir.path().join("out/haproxy.log.gz");

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let download = session.download(
            &file,
            &dest,
            None,
            move |received| {
                let _ = tx.send(received);
            },
            CancellationToken::new(),
        );
        let killer = async {
            // Dès que des octets arrivent, le serveur cible coupe la connexion.
            rx.recv().await;
            env.target.disconnect_all().await;
        };
        let (result, ()) = tokio::join!(download, killer);
        assert!(
            matches!(result, Err(RemoteError::TransferInterrupted { .. })),
            "{result:?}"
        );
        assert!(!dest.exists());
        assert!(!env.dir.path().join("out/haproxy.log.gz.part").exists());
    })
    .await;
}

// ---------------------------------------------------------------------------
// Connexion : erreurs, direct-tcpip, TOFU, clés
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cle_refusee_par_le_bastion_puis_par_la_cible() {
    bounded(async {
        let env = Env::start().await;
        let stranger = env.dir.path().join("id_inconnu");
        common::new_key()
            .write_openssh_file(&stranger, russh::keys::ssh_key::LineEnding::LF)
            .unwrap();

        // Clé inconnue du bastion.
        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.auth = AuthConfig::Key {
            identity_file: stranger.display().to_string(),
        };
        let pool = SessionPool::new(bastion, ConnectOptions::default());
        match pool.session(&env.server()).await {
            Err(RemoteError::KeyRejected { host, user }) => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(user, "testeur");
            }
            other => panic!("attendu KeyRejected, obtenu {other:?}"),
        }
        assert_eq!(env.target.connections(), 0);

        // Bastion d'accord, cible non (clé propre au serveur).
        let pool = env.pool(JumpMode::Nc);
        let mut server = env.server();
        server.user = Some("autre".into());
        server.auth = Some(AuthConfig::Key {
            identity_file: stranger.display().to_string(),
        });
        match pool.session(&server).await {
            Err(RemoteError::KeyRejected { user, .. }) => assert_eq!(user, "autre"),
            other => panic!("attendu KeyRejected, obtenu {other:?}"),
        }
        assert_eq!(env.target.connections(), 1);

        // Fichier de clé absent.
        let mut server = env.server();
        server.auth = Some(AuthConfig::Key {
            identity_file: "/nulle/part/id_rsa".into(),
        });
        assert!(matches!(
            pool.session(&server).await,
            Err(RemoteError::KeyUnreadable { .. })
        ));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cible_et_bastion_injoignables() {
    bounded(async {
        let env = Env::start().await;
        let dead = closed_port().await;

        // Mode nc : `nc` échoue sur le bastion, son message remonte.
        let pool = env.pool(JumpMode::Nc);
        let mut server = env.server();
        server.port = dead;
        match pool.session(&server).await {
            Err(RemoteError::TargetUnreachable { host, port, detail }) => {
                assert_eq!((host.as_str(), port), ("127.0.0.1", dead));
                assert!(!detail.is_empty());
                println!("détail nc : {detail}");
            }
            other => panic!("attendu TargetUnreachable, obtenu {other:?}"),
        }
        // Le bastion, lui, reste connecté et sert au serveur suivant.
        pool.session(&env.server()).await.unwrap();
        assert_eq!(env.bastion.connections(), 1);

        // Commande nc introuvable sur le bastion.
        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.nc_command = "nc-absent {host} {port}".into();
        let pool = SessionPool::new(bastion, ConnectOptions::default());
        match pool.session(&env.server()).await {
            Err(RemoteError::TargetUnreachable { detail, .. }) => {
                assert!(detail.contains("nc-absent"), "{detail}")
            }
            other => panic!("attendu TargetUnreachable, obtenu {other:?}"),
        }

        // Mode direct-tcpip.
        let pool = env.pool(JumpMode::DirectTcpip);
        assert!(matches!(
            pool.session(&server).await,
            Err(RemoteError::TargetUnreachable { .. })
        ));

        // Bastion injoignable.
        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.port = dead;
        let pool = SessionPool::new(bastion, ConnectOptions::default());
        match pool.session(&env.server()).await {
            Err(e @ RemoteError::BastionUnreachable { .. }) => {
                assert_eq!(e.code(), "bastion_unreachable")
            }
            other => panic!("attendu BastionUnreachable, obtenu {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mode_direct_tcpip_de_bout_en_bout() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::DirectTcpip);
        let session = pool.session(&env.server()).await.unwrap();
        assert!(
            env.bastion.commands().is_empty(),
            "aucun nc en mode direct-tcpip"
        );

        let apps = session.discover_apps(day()).await.unwrap();
        assert_eq!(apps.len(), 3);
        let file = file_of(&session, "etam_sb_gateway", "etam-sb", LogKind::Erlang).await;
        let dest = env.dir.path().join("out/erlang.log.gz");
        session
            .download(&file, &dest, None, |_| {}, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(gunzip(&std::fs::read(&dest).unwrap()), ERLANG_GATEWAY);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tofu_premier_contact_puis_cle_changee() {
    bounded(async {
        let env = Env::start().await;
        let known_hosts = env.dir.path().join("etat/known_hosts.json");
        let options = ConnectOptions {
            known_hosts_path: Some(known_hosts.clone()),
            ..Default::default()
        };
        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.host_key_policy = HostKeyPolicy::Tofu;

        // TOFU sans fichier : erreur de configuration, pas de connexion.
        let pool = SessionPool::new(bastion.clone(), ConnectOptions::default());
        assert!(matches!(
            pool.session(&env.server()).await,
            Err(RemoteError::InvalidConfig { .. })
        ));
        assert_eq!(env.bastion.connections(), 0);

        // Premier contact : accepté et enregistré (bastion et cible).
        let pool = SessionPool::new(bastion.clone(), options.clone());
        pool.session(&env.server()).await.unwrap();
        pool.close().await;
        let stored = std::fs::read_to_string(&known_hosts).unwrap();
        assert!(
            stored.contains(&format!("127.0.0.1:{}", env.bastion.port)),
            "{stored}"
        );
        assert!(
            stored.contains(&format!("127.0.0.1:{}", env.target.port)),
            "{stored}"
        );
        assert!(stored.contains("SHA256:"), "{stored}");

        // Mêmes clés : toujours accepté.
        let pool = SessionPool::new(bastion.clone(), options.clone());
        pool.session(&env.server()).await.unwrap();
        pool.close().await;

        // La cible change de clé : refus typé.
        env.target.rotate_host_key();
        let pool = SessionPool::new(bastion.clone(), options.clone());
        match pool.session(&env.server()).await {
            Err(RemoteError::HostKeyChanged {
                host,
                port,
                expected,
                actual,
            }) => {
                assert_eq!((host.as_str(), port), ("127.0.0.1", env.target.port));
                assert!(expected.starts_with("SHA256:") && actual.starts_with("SHA256:"));
                assert_ne!(expected, actual);
            }
            other => panic!("attendu HostKeyChanged, obtenu {other:?}"),
        }
        // Le fichier n'a pas été modifié par le refus.
        assert_eq!(std::fs::read_to_string(&known_hosts).unwrap(), stored);

        // Le bastion change de clé : refus aussi.
        env.bastion.rotate_host_key();
        let pool = SessionPool::new(bastion, options);
        match pool.session(&env.server2()).await {
            Err(RemoteError::HostKeyChanged { port, .. }) => assert_eq!(port, env.bastion.port),
            other => panic!("attendu HostKeyChanged, obtenu {other:?}"),
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cle_chiffree_phrase_de_passe() {
    bounded(async {
        let env = Env::start().await;
        let key = common::new_key();
        env.bastion.authorize(key.public_key().clone());
        env.target.authorize(key.public_key().clone());
        let path = env.dir.path().join("id_chiffree");
        key.encrypt(&mut russh::keys::key::safe_rng(), "phrase d'essai")
            .unwrap()
            .write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        let identity_file = path.display().to_string();

        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.auth = AuthConfig::Key {
            identity_file: identity_file.clone(),
        };
        let pool = SessionPool::new(bastion, ConnectOptions::default());

        match pool.session(&env.server()).await {
            Err(RemoteError::KeyPassphraseRequired { identity_file: f }) => {
                assert_eq!(f, identity_file)
            }
            other => panic!("attendu KeyPassphraseRequired, obtenu {other:?}"),
        }

        pool.set_key_passphrase(&identity_file, Some(secret("mauvaise")));
        let err = pool.session(&env.server()).await.unwrap_err();
        assert!(
            matches!(err, RemoteError::KeyPassphraseInvalid { .. }),
            "{err:?}"
        );
        assert!(!format!("{err} {err:?}").contains("mauvaise"));

        pool.set_key_passphrase(&identity_file, Some(secret("phrase d'essai")));
        let session = pool.session(&env.server()).await.unwrap();
        assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cle_rsa_au_format_pem_signee_en_rsa_sha2() {
    bounded(async {
        let env = Env::start().await;
        // Une vraie `id_rsa` comme en produit `ssh-keygen -m PEM`.
        let path = env.dir.path().join("id_rsa");
        let generated = std::process::Command::new("ssh-keygen")
            .args([
                "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-C", "test", "-f",
            ])
            .arg(&path)
            .status();
        if !matches!(generated, Ok(s) if s.success()) {
            eprintln!("ssh-keygen indisponible : test RSA sauté");
            return;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("BEGIN RSA PRIVATE KEY"), "format PEM attendu");
        let public = russh::keys::load_public_key(path.with_extension("pub")).unwrap();
        env.bastion.authorize(public.clone());
        env.target.authorize(public);

        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.auth = AuthConfig::Key {
            identity_file: path.display().to_string(),
        };
        let pool = SessionPool::new(bastion, ConnectOptions::default());
        let session = pool.session(&env.server()).await.unwrap();
        assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");

        for server in [&env.bastion, &env.target] {
            let algorithms = server.auth_algorithms();
            assert_eq!(algorithms.len(), 1, "{algorithms:?}");
            assert!(
                algorithms[0] == "rsa-sha2-512" || algorithms[0] == "rsa-sha2-256",
                "signature RSA SHA-2 attendue, obtenu {algorithms:?}"
            );
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn le_pool_reutilise_les_sessions() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);

        // Deux serveurs demandés en même temps : une seule connexion bastion.
        let (server1, server2) = (env.server(), env.server2());
        let (s1, s2) = tokio::join!(pool.session(&server1), pool.session(&server2));
        let (s1, s2) = (s1.unwrap(), s2.unwrap());
        assert_eq!(env.bastion.connections(), 1);
        assert_eq!(env.target.connections(), 1);
        assert_eq!(env.target2.connections(), 1);

        // Redemander un serveur rend la même session.
        let again = pool.session(&env.server()).await.unwrap();
        assert!(Arc::ptr_eq(&s1, &again));
        assert!(!Arc::ptr_eq(&s1, &s2));
        assert_eq!(env.target.connections(), 1);
        let stats = pool.stats();
        assert_eq!(
            (stats.bastion_connections, stats.target_connections),
            (1, 2)
        );

        // Les deux sessions travaillent en parallèle à travers le même bastion.
        let (a, b) = tokio::join!(s1.discover_apps(day()), s2.discover_apps(day()));
        assert_eq!(a.unwrap(), b.unwrap());
        assert_eq!(s1.server().id, "etam-sb");
        assert_eq!(s2.server().id, "jar-sb");

        pool.close().await;
        assert!(!s1.is_alive() || wait_dead(&s1).await);
    })
    .await;
}

async fn wait_dead(session: &logano_remote::RemoteSession) -> bool {
    for _ in 0..200 {
        if !session.is_alive() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn le_pool_reconnecte_une_session_morte() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let first = pool.session(&env.server()).await.unwrap();

        // La cible coupe : nouvelle session cible, même bastion.
        env.target.disconnect_all().await;
        assert!(wait_dead(&first).await, "la session doit être vue morte");
        assert!(first.exec("echo x").await.is_err());
        let second = pool.session(&env.server()).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.exec("echo ok").await.unwrap().stdout, b"ok\n");
        assert_eq!(env.bastion.connections(), 1);
        assert_eq!(env.target.connections(), 2);

        // Le bastion coupe : tout est rouvert.
        env.bastion.disconnect_all().await;
        assert!(wait_dead(&second).await);
        let third = pool.session(&env.server()).await.unwrap();
        assert_eq!(third.exec("echo ok").await.unwrap().stdout, b"ok\n");
        assert_eq!(env.bastion.connections(), 2);
        assert_eq!(pool.stats().bastion_connections, 2);

        // Changer la config d'un serveur (même id) ouvre une nouvelle session.
        let mut moved = env.server();
        moved.port = env.target2.port;
        let fourth = pool.session(&moved).await.unwrap();
        assert!(!Arc::ptr_eq(&third, &fourth));
        assert_eq!(env.target2.connections(), 1);
    })
    .await;
}

// ---------------------------------------------------------------------------
// Cache + téléchargement
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_valable_puis_perime_quand_le_fichier_du_jour_grossit() {
    bounded(async {
        let env = Env::start().await;
        let pool = env.pool(JumpMode::Nc);
        let session = pool.session(&env.server()).await.unwrap();
        let cache = RawCache::new(env.dir.path().join("cache/raw"));
        let (app, cluster) = ("jar_sb_admin", "jar-sb-atlas");

        let file = file_of(&session, app, cluster, LogKind::Erlang).await;
        assert_eq!(
            cache.lookup("etam-sb", day(), app, cluster, &file),
            CacheLookup::Missing
        );

        let dest = cache.path_for("etam-sb", day(), app, cluster, file.kind);
        assert!(dest.ends_with("etam-sb/2026/11/09/jar_sb_admin/jar-sb-atlas/erlang.log.gz"));
        let outcome = session
            .download(&file, &dest, None, |_| {}, CancellationToken::new())
            .await
            .unwrap();
        cache
            .write_meta("etam-sb", day(), app, cluster, &file, true)
            .unwrap();

        match cache.lookup("etam-sb", day(), app, cluster, &file) {
            CacheLookup::Valid { path, meta } => {
                assert_eq!(path, dest);
                assert_eq!(meta.remote_size, file.size);
                assert!(meta.complete);
            }
            other => panic!("attendu Valid, obtenu {other:?}"),
        }
        assert!(cache.size().unwrap() >= outcome.bytes);

        // Le fichier distant grossit : l'entrée devient périmée.
        let remote = env.log_path("jar_sb_admin/jar-sb-atlas/erlang.log");
        let mut content = std::fs::read(&remote).unwrap();
        content.extend_from_slice(b"une ligne de plus\n");
        std::fs::write(&remote, content).unwrap();
        let grown = file_of(&session, app, cluster, LogKind::Erlang).await;
        assert!(grown.size > file.size);
        assert!(matches!(
            cache.lookup("etam-sb", day(), app, cluster, &grown),
            CacheLookup::Stale {
                reason: StaleReason::SizeChanged,
                ..
            }
        ));

        cache.purge().unwrap();
        assert_eq!(cache.size().unwrap(), 0);
        assert_eq!(
            cache.lookup("etam-sb", day(), app, cluster, &file),
            CacheLookup::Missing
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// Garanties de compilation : l'app lance ces opérations dans des tâches tokio.
// ---------------------------------------------------------------------------

fn assert_send<T: Send>(_: T) {}
fn assert_send_sync<T: Send + Sync>() {}

#[allow(dead_code)]
fn les_futures_sont_send(
    pool: Arc<SessionPool>,
    session: Arc<logano_remote::RemoteSession>,
    server: logano_remote::ServerConfig,
    file: RemoteFile,
    password: SecretString,
) {
    assert_send_sync::<SessionPool>();
    assert_send_sync::<logano_remote::RemoteSession>();
    assert_send_sync::<RemoteError>();
    assert_send(pool.session(&server));
    assert_send(pool.close());
    assert_send(session.exec("true"));
    assert_send(session.exec_with_stdin("true", Some(b"x")));
    assert_send(session.exec_stream("true"));
    assert_send(session.discover_apps(day()));
    assert_send(session.list_files(day(), "a", "c"));
    assert_send(session.ensure_readable(&["/x"], Some(&password)));
    assert_send(session.download(
        &file,
        std::path::Path::new("/x"),
        Some(&password),
        |_| {},
        CancellationToken::new(),
    ));
}

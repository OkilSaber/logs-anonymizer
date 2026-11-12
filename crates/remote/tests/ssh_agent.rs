//! Authentification par ssh-agent, contre un vrai `ssh-agent` lancé pour le
//! test. Ce fichier ne contient qu'un seul test : il modifie `SSH_AUTH_SOCK`
//! pour tout le processus, ce qui ne doit pas se faire à côté d'autres tests.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::{bounded, Env};
use logano_remote::{AuthConfig, ConnectOptions, JumpMode, RemoteError, SessionPool};

struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ssh_add(sock: &Path, args: &[&str]) -> bool {
    Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentification_par_ssh_agent() {
    bounded(async {
        let env = Env::start().await;
        let sock = env.dir.path().join("agent.sock");
        let spawned = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(child) = spawned else {
            eprintln!("ssh-agent indisponible : test sauté");
            return;
        };
        let _agent = Agent(child);
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if !sock.exists() {
            eprintln!("ssh-agent n'a pas créé son socket : test sauté");
            return;
        }

        let mut bastion = env.bastion_config(JumpMode::Nc);
        bastion.auth = AuthConfig::Agent;
        let pool = |b: &logano_remote::BastionConfig| {
            SessionPool::new(b.clone(), ConnectOptions::default())
        };

        // SSH_AUTH_SOCK absent.
        std::env::remove_var("SSH_AUTH_SOCK");
        assert!(matches!(
            pool(&bastion).session(&env.server()).await,
            Err(RemoteError::AgentUnavailable { .. })
        ));

        // Agent vide.
        std::env::set_var("SSH_AUTH_SOCK", &sock);
        assert!(matches!(
            pool(&bastion).session(&env.server()).await,
            Err(RemoteError::AgentUnavailable { .. })
        ));

        // Agent qui ne détient qu'une clé inconnue des serveurs.
        let stranger = env.dir.path().join("id_inconnu");
        common::new_key()
            .write_openssh_file(&stranger, russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        assert!(
            ssh_add(&sock, &[stranger.to_str().unwrap()]),
            "ssh-add a échoué"
        );
        assert!(matches!(
            pool(&bastion).session(&env.server()).await,
            Err(RemoteError::KeyRejected { .. })
        ));

        // Avec la bonne clé (en plus de l'autre) : bastion et cible acceptent.
        assert!(
            ssh_add(&sock, &[env.client_key_path.to_str().unwrap()]),
            "ssh-add a échoué"
        );
        let pool = pool(&bastion);
        let session = pool.session(&env.server()).await.unwrap();
        assert_eq!(session.exec("echo ok").await.unwrap().stdout, b"ok\n");
        assert_eq!(env.bastion.auth_algorithms(), vec!["ssh-ed25519"]);
        assert_eq!(env.target.auth_algorithms(), vec!["ssh-ed25519"]);
    })
    .await;
}

//! Pool de sessions : une session bastion partagée, une session par serveur.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{BastionConfig, ServerConfig};
use crate::error::{RemoteError, Result};
use crate::session::{
    connect_bastion, connect_target, BastionLink, ConnectOptions, Credentials, RemoteSession,
};

/// Compteurs cumulés du pool (diagnostic et tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// Nombre de connexions ouvertes vers un bastion depuis la création du pool.
    pub bastion_connections: usize,
    /// Nombre de connexions ouvertes vers un serveur cible.
    pub target_connections: usize,
}

type TargetSlot = Arc<AsyncMutex<Option<Arc<RemoteSession>>>>;

/// Garde les sessions SSH ouvertes pendant toute une extraction.
///
/// - une seule session par bastion, réutilisée pour tous les serveurs ;
/// - une session par serveur cible, rendue sous forme d'`Arc<RemoteSession>` ;
/// - une session morte est remplacée au prochain appel de [`session`](Self::session).
pub struct SessionPool {
    bastion: BastionConfig,
    creds: Arc<Credentials>,
    bastions: AsyncMutex<HashMap<String, Arc<BastionLink>>>,
    targets: Mutex<HashMap<String, TargetSlot>>,
    bastion_connections: AtomicUsize,
    target_connections: AtomicUsize,
}

impl SessionPool {
    /// Crée un pool vide. Aucune connexion n'est ouverte avant le premier
    /// appel de [`session`](Self::session).
    pub fn new(bastion: BastionConfig, options: ConnectOptions) -> Self {
        SessionPool {
            bastion,
            creds: Arc::new(Credentials::new(options)),
            bastions: AsyncMutex::new(HashMap::new()),
            targets: Mutex::new(HashMap::new()),
            bastion_connections: AtomicUsize::new(0),
            target_connections: AtomicUsize::new(0),
        }
    }

    /// Bastion global du pool.
    pub fn bastion(&self) -> &BastionConfig {
        &self.bastion
    }

    /// Fournit (ou retire, avec `None`) la phrase de passe d'une clé chiffrée.
    /// `identity_file` est le chemin tel qu'il apparaît dans la config et dans
    /// [`RemoteError::KeyPassphraseRequired`]. Gardée en mémoire uniquement.
    pub fn set_key_passphrase(&self, identity_file: &str, passphrase: Option<SecretString>) {
        self.creds.set_passphrase(identity_file, passphrase);
    }

    /// Rend la session du serveur, en la créant (et en créant celle du
    /// bastion) si nécessaire. Deux appels pour le même serveur rendent le
    /// même `Arc` tant que la session est vivante.
    pub async fn session(&self, server: &ServerConfig) -> Result<Arc<RemoteSession>> {
        let slot = self
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(server.id.clone())
            .or_default()
            .clone();
        // Un seul appelant à la fois ouvre la session d'un serveur donné.
        let mut slot = slot.lock().await;
        if let Some(session) = slot.as_ref() {
            if session.is_alive() && session.server() == server {
                return Ok(session.clone());
            }
            session.close().await;
            *slot = None;
        }

        let mut last_error = None;
        for _ in 0..2 {
            let link = self
                .bastion_link(server.effective_bastion(&self.bastion))
                .await?;
            match connect_target(link.clone(), server, &self.bastion, &self.creds).await {
                Ok(session) => {
                    self.target_connections.fetch_add(1, Ordering::Relaxed);
                    let session = Arc::new(session);
                    *slot = Some(session.clone());
                    return Ok(session);
                }
                // Le bastion est tombé entre-temps : on le rouvre une fois.
                Err(e @ RemoteError::BastionUnreachable { .. }) if !link.is_alive() => {
                    last_error = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_error.expect("deux tentatives ont échoué"))
    }

    async fn bastion_link(&self, cfg: &BastionConfig) -> Result<Arc<BastionLink>> {
        let key = format!("{}@{}:{}", cfg.user, cfg.host, cfg.port);
        let mut bastions = self.bastions.lock().await;
        if let Some(link) = bastions.get(&key) {
            if link.is_alive() && &link.cfg == cfg {
                return Ok(link.clone());
            }
            link.close().await;
            bastions.remove(&key);
        }
        let link = Arc::new(connect_bastion(cfg, &self.creds).await?);
        self.bastion_connections.fetch_add(1, Ordering::Relaxed);
        bastions.insert(key, link.clone());
        Ok(link)
    }

    /// Ferme toutes les sessions. Le pool reste utilisable : le prochain
    /// appel de [`session`](Self::session) rouvrira ce qu'il faut.
    pub async fn close(&self) {
        let slots: Vec<TargetSlot> = self
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, slot)| slot)
            .collect();
        for slot in slots {
            if let Some(session) = slot.lock().await.take() {
                session.close().await;
            }
        }
        let mut bastions = self.bastions.lock().await;
        for (_, link) in bastions.drain() {
            link.close().await;
        }
    }

    /// Compteurs de connexions ouvertes depuis la création du pool.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            bastion_connections: self.bastion_connections.load(Ordering::Relaxed),
            target_connections: self.target_connections.load(Ordering::Relaxed),
        }
    }
}

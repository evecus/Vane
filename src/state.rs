use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use tokio::{fs, sync::RwLock};

use crate::{
    auth::hash_password,
    engines::RuntimeEngines,
    models::{AdminConfig, Config, RuntimeData},
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub data: Arc<RwLock<RuntimeData>>,
    pub sessions: Arc<RwLock<HashMap<String, String>>>,      // token -> username
    pub session_expiry: Arc<RwLock<HashMap<String, i64>>>,   // token -> unix timestamp
    pub login_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>, // ip -> (count, window_start)
    pub engines: RuntimeEngines,
    pub root: PathBuf,
}

impl AppState {
    pub async fn load(root: PathBuf) -> anyhow::Result<Self> {
        let cfg_path = root.join("vane.json");
        let data_path = root.join("runtime.json");

        let cfg: Config = match fs::read_to_string(&cfg_path).await {
            Ok(s) => serde_json::from_str(&s).context("parse vane.json")?,
            Err(_) => {
                let d = Config {
                    admin: AdminConfig {
                        username: "admin".into(),
                        password_hash: hash_password("vane1234")?,
                        port: 4455,
                        safe_entry: String::new(),
                        welcome_shown: false,
                    },
                };
                fs::write(&cfg_path, serde_json::to_vec_pretty(&d)?).await?;
                d
            }
        };

        let data: RuntimeData = match fs::read_to_string(&data_path).await {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => RuntimeData::default(),
        };

        Ok(Self {
            config: Arc::new(RwLock::new(cfg)),
            data: Arc::new(RwLock::new(data)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_expiry: Arc::new(RwLock::new(HashMap::new())),
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
            engines: RuntimeEngines::default(),
            root,
        })
    }

    pub async fn persist_all(&self) -> anyhow::Result<()> {
        fs::write(
            self.root.join("vane.json"),
            serde_json::to_vec_pretty(&*self.config.read().await)?,
        )
        .await?;
        fs::write(
            self.root.join("runtime.json"),
            serde_json::to_vec_pretty(&*self.data.read().await)?,
        )
        .await?;
        Ok(())
    }

    /// Apply all enabled engine rules (reconcile running tasks vs config).
    pub async fn apply_engines(&self) {
        let d = self.data.read().await.clone();
        self.engines.apply_portforwards(&d.portforward).await;
        self.engines.apply_ddns(&d.ddns, self.data.clone()).await;
        self.engines.apply_webservice(&d.webservice).await;
        self.engines.apply_tls(&d.tls, self.data.clone(), self.config.read().await.clone()).await;
    }

    /// Expire old sessions and clean up stale login-attempt windows.
    pub async fn cleanup_security_state(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut exp = self.session_expiry.write().await;
        let mut sess = self.sessions.write().await;
        let expired: Vec<String> = exp
            .iter()
            .filter(|(_, v)| **v <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for t in expired {
            exp.remove(&t);
            sess.remove(&t);
        }

        // Clean login attempts older than 30 minutes
        let mut la = self.login_attempts.write().await;
        la.retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(1800));
    }

    /// Extend session expiry (sliding 24h window).
    pub async fn touch_session(&self, token: &str) {
        let new_exp = chrono::Utc::now().timestamp() + 86400;
        self.session_expiry
            .write()
            .await
            .insert(token.to_string(), new_exp);
    }

    /// Clear all active sessions (called after port/safe_entry change).
    pub async fn clear_all_sessions(&self) {
        self.sessions.write().await.clear();
        self.session_expiry.write().await.clear();
        // Also clear sessions_meta so the UI sessions list is in sync
        self.data.write().await.sessions_meta.clear();
    }
}

/// Generate a new unique ID (UUID v4 style hex string).
pub fn new_id() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes(buf[0..4].try_into().unwrap()),
        u16::from_be_bytes(buf[4..6].try_into().unwrap()),
        u16::from_be_bytes(buf[6..8].try_into().unwrap()) & 0x0fff,
        (u16::from_be_bytes(buf[8..10].try_into().unwrap()) & 0x3fff) | 0x8000,
        {
            let mut x = [0u8; 8];
            x[2..8].copy_from_slice(&buf[10..16]);
            u64::from_be_bytes(x)
        }
    )
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

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

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub data: Arc<RwLock<RuntimeData>>,
    pub sessions: Arc<RwLock<HashMap<String, String>>>,
    pub session_expiry: Arc<RwLock<HashMap<String, i64>>>,
    pub login_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
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
}

impl AppState {
    pub async fn apply_engines(&self) {
        let d = self.data.read().await.clone();
        self.engines.apply_portforwards(&d.portforward).await;
        self.engines.apply_ddns(&d.ddns).await;
        self.engines.apply_webservice(&d.webservice).await;
        self.engines.apply_tls(&d.tls).await;
    }
}

impl AppState {
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

        let mut la = self.login_attempts.write().await;
        la.retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(1800));
    }
}

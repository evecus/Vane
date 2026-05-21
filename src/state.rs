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
    db::Db,
    engines::{rematch_all_routes, RuntimeEngines},
    models::{AdminConfig, Config, RuntimeData},
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub data: Arc<RwLock<RuntimeData>>,
    /// token -> (username, expires_unix)
    pub sessions: Arc<RwLock<HashMap<String, (String, i64)>>>,
    pub login_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    pub engines: RuntimeEngines,
    pub root: PathBuf,
    pub db: Db,
}

impl AppState {
    pub async fn load(root: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&root).await?;

        // Open DB (creates secret.key + vane.db if first run)
        let db = Db::open(&root).await.context("open database")?;

        // Load admin config from DB; init defaults on first run
        let admin = match db.load_admin().await? {
            Some(a) => a,
            None => {
                let a = AdminConfig {
                    username: "admin".into(),
                    password_hash: hash_password("admin")?,
                    port: 4455,
                    safe_entry: String::new(),
                    welcome_shown: false,
                };
                db.save_admin(&a).await?;
                a
            }
        };

        let cfg = Config { admin };

        // Load all runtime data from DB
        let mut data = RuntimeData {
            portforward: db.load_port_forwards().await?,
            ddns: db.load_ddns().await?,
            webservice: db.load_web_services().await?,
            tls: db.load_tls_certs().await?,
            ipfilter: db.load_ip_filters().await?,
            access_logs: vec![],   // loaded on demand from DB
            admin_logs: vec![],    // loaded on demand from DB
            sessions_meta: vec![], // managed by sessions map
        };

        // Normalize port forward rules (Go-style field compatibility)
        for pf in &mut data.portforward {
            pf.normalize();
        }

        // Restore in-memory sessions from DB
        let mut sessions = HashMap::new();
        let now = chrono::Utc::now().timestamp();
        db.delete_expired_sessions(now).await?;
        for s in db.load_sessions().await? {
            // expires_at is stored; for in-memory we track (username, expiry)
            sessions.insert(s.token.clone(), (s.username.clone(), now + 86400));
        }

        Ok(Self {
            config: Arc::new(RwLock::new(cfg)),
            data: Arc::new(RwLock::new(data)),
            sessions: Arc::new(RwLock::new(sessions)),
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
            engines: RuntimeEngines::default(),
            root,
            db,
        })
    }

    // ─── Session helpers ──────────────────────────────────────────────────────

    /// Check if a session token is valid. Also slides the expiry window.
    pub async fn is_session_valid(&self, token: &str) -> bool {
        let now = chrono::Utc::now().timestamp();
        let sessions = self.sessions.read().await;
        if let Some((_, exp)) = sessions.get(token) {
            *exp > now
        } else {
            false
        }
    }

    pub async fn add_session(&self, token: &str, username: &str) {
        let exp = chrono::Utc::now().timestamp() + 86400;
        self.sessions
            .write()
            .await
            .insert(token.to_string(), (username.to_string(), exp));
        let _ = self.db.save_session(token, username, exp).await;
    }

    pub async fn remove_session(&self, token: &str) {
        self.sessions.write().await.remove(token);
        let _ = self.db.delete_session(token).await;
    }

    pub async fn touch_session(&self, token: &str) {
        let new_exp = chrono::Utc::now().timestamp() + 86400;
        if let Some(entry) = self.sessions.write().await.get_mut(token) {
            entry.1 = new_exp;
        }
        let _ = self.db.touch_session(token, new_exp).await;
    }

    pub async fn clear_all_sessions(&self) {
        self.sessions.write().await.clear();
        let _ = self.db.delete_all_sessions().await;
    }

    pub async fn get_session_username(&self, token: &str) -> Option<String> {
        self.sessions
            .read()
            .await
            .get(token)
            .map(|(u, _)| u.clone())
    }

    // ─── Cleanup ──────────────────────────────────────────────────────────────

    pub async fn cleanup_security_state(&self) {
        let now = chrono::Utc::now().timestamp();
        let _ = self.db.delete_expired_sessions(now).await;
        self.sessions.write().await.retain(|_, (_, exp)| *exp > now);
        self.login_attempts
            .write()
            .await
            .retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(1800));
    }

    // ─── Engine reconciliation ────────────────────────────────────────────────

    pub async fn apply_engines(&self) {
        let d = self.data.read().await.clone();
        self.engines
            .apply_portforwards(&d.portforward, self.data.clone())
            .await;
        self.engines
            .apply_ddns(&d.ddns, self.data.clone(), self.db.clone())
            .await;
        self.engines
            .apply_webservice(
                &d.webservice,
                &d.tls,
                &d.ipfilter,
                self.db.clone(),
                self.data.clone(),
            )
            .await;
        self.engines
            .apply_tls(
                &d.tls,
                self.data.clone(),
                self.config.read().await.clone(),
                self.db.clone(),
            )
            .await;
    }

    pub async fn rematch_and_restart(&self) {
        rematch_all_routes(&self.data).await;
        let d = self.data.read().await.clone();
        self.engines
            .apply_webservice(
                &d.webservice,
                &d.tls,
                &d.ipfilter,
                self.db.clone(),
                self.data.clone(),
            )
            .await;
    }
}

/// Generate a new unique ID (UUID v4 style).
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

impl AppState {
    /// Persist the current in-memory state to the database.
    /// Called after every mutation so that all data is durably stored encrypted.
    pub async fn db_persist_current(
        &self,
        data: &crate::models::RuntimeData,
        _cfg: &Config,
    ) -> anyhow::Result<()> {
        // Save admin config
        self.db.save_admin(&_cfg.admin).await?;
        // Save all port forwards
        for r in &data.portforward {
            self.db.save_port_forward(r).await?;
        }
        // Save all DDNS rules
        for r in &data.ddns {
            self.db.save_ddns(r).await?;
        }
        // Save all web services + routes
        for svc in &data.webservice {
            self.db.save_web_service(svc).await?;
            for route in &svc.routes {
                self.db.save_web_route(&svc.id, route).await?;
            }
        }
        // Save all TLS certs
        for cert in &data.tls {
            self.db.save_tls_cert(cert).await?;
        }
        // Save all IP filter rules
        for rule in &data.ipfilter {
            self.db.save_ip_filter(rule).await?;
        }
        Ok(())
    }
}

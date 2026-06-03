pub mod crypto;
pub mod db;
pub mod ipfilter;
pub mod types;

pub use db::DataDir;
pub use ipfilter::{check_ip_allowed, clean_scopes_for_deleted_target};
pub use types::*;

use anyhow::Result;
use std::sync::{Arc, RwLock};

// ─── Config (shared mutable state) ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config(Arc<RwLock<ConfigInner>>);

#[derive(Debug, Default)]
pub struct ConfigInner {
    pub admin: AdminConfig,
    pub port_forwards: Vec<PortForwardRule>,
    pub ddns: Vec<DdnsRule>,
    pub web_services: Vec<WebService>,
    pub tls_certs: Vec<TlsCert>,
    pub ip_filter: Vec<IpFilterRule>,
    pub data_dir: Option<Arc<DataDir>>,
}

impl Config {
    pub fn new(inner: ConfigInner) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, ConfigInner> {
        self.0.read().unwrap()
    }

    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, ConfigInner> {
        self.0.write().unwrap()
    }

    pub fn check_ip_allowed(&self, scope_type: &str, target_id: &str, client_ip: &str) -> bool {
        let inner = self.read();
        check_ip_allowed(&inner.ip_filter, scope_type, target_id, client_ip)
    }

    /// Remove stale scope entries left behind when a portforward/webservice target
    /// is deleted.  Returns the (cloned) rules that were modified so the caller
    /// can persist them.
    pub fn clean_scopes_for_deleted_target(
        &self,
        scope_type: &str,
        target_id: &str,
    ) -> Vec<crate::config::types::IpFilterRule> {
        let mut inner = self.write();
        let modified_ids =
            clean_scopes_for_deleted_target(&mut inner.ip_filter, scope_type, target_id);
        inner
            .ip_filter
            .iter()
            .filter(|r| modified_ids.contains(&r.id))
            .cloned()
            .collect()
    }
}

// ─── Load from DB ─────────────────────────────────────────────────────────────

pub fn load(dd: Arc<DataDir>) -> Result<Config> {
    let inner = db::load_from_db(&dd)?;
    let mut cfg_inner = inner;
    cfg_inner.data_dir = Some(dd);
    Ok(Config::new(cfg_inner))
}

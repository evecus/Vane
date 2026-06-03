pub mod crypto;
pub mod db;
pub mod ipfilter;
pub mod types;

pub use db::DataDir;
pub use ipfilter::{clean_scopes_for_deleted_target, IpFilterCache};
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
    /// 预编译缓存，随 ip_filter 同步更新，查询时直接使用。
    pub ip_filter_cache: IpFilterCache,
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

    /// 每次 ip_filter 发生增删改后调用，重建预编译缓存。
    pub fn rebuild_ip_filter_cache(&self) {
        let mut inner = self.write();
        inner.ip_filter_cache = IpFilterCache::rebuild(&inner.ip_filter);
    }

    /// 查询 client_ip 是否被允许访问指定 scope，直接走预编译缓存。
    pub fn check_ip_allowed(&self, scope_type: &str, target_id: &str, client_ip: &str) -> bool {
        let inner = self.read();
        inner
            .ip_filter_cache
            .check_allowed(scope_type, target_id, client_ip)
    }

    /// 删除 portforward/webservice 目标时清理 scopes，返回被修改的规则供调用方持久化。
    pub fn clean_scopes_for_deleted_target(
        &self,
        scope_type: &str,
        target_id: &str,
    ) -> Vec<crate::config::types::IpFilterRule> {
        let mut inner = self.write();
        let modified_ids =
            clean_scopes_for_deleted_target(&mut inner.ip_filter, scope_type, target_id);
        // 顺便重建缓存（scopes 变了，虽然 IP 集合不变，但保持一致）
        inner.ip_filter_cache = IpFilterCache::rebuild(&inner.ip_filter);
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
    // 启动时从持久化数据构建一次缓存
    cfg_inner.ip_filter_cache = IpFilterCache::rebuild(&cfg_inner.ip_filter);
    Ok(Config::new(cfg_inner))
}

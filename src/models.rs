use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    pub password_hash: String,
    pub port: u16,
    pub safe_entry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortForwardRule {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen: String,
    pub target: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DdnsRule {
    pub id: String,
    pub provider: String,
    pub domain: String,
    pub record_type: String,
    pub token: String,
    pub zone: String,
    pub record_name: String,
    pub proxied: bool,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebServiceRule {
    pub id: String,
    pub domain: String,
    pub backend: String,
    pub listen: String,
    pub force_https: bool,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsRule {
    pub id: String,
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterRule {
    pub id: String,
    pub target: String,
    pub target_id: String,
    pub cidr: String,
    pub action: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeData {
    pub portforward: Vec<PortForwardRule>,
    pub ddns: Vec<DdnsRule>,
    pub webservice: Vec<WebServiceRule>,
    pub tls: Vec<TlsRule>,
    pub ipfilter: Vec<IpFilterRule>,
    pub web_routes: std::collections::HashMap<String, Vec<WebRoute>>,
    pub access_logs: Vec<AccessLog>,
    pub tls_artifacts: Vec<TlsArtifact>,
    pub admin_logs: Vec<AdminLogRecord>,
    pub sessions_meta: Vec<SessionInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct PortForwardStats {
    pub id: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct WebRoute {
    pub id: String,
    pub path: String,
    pub backend: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AccessLog {
    pub ts: String,
    pub service_id: String,
    pub route_id: String,
    pub client_ip: String,
    pub path: String,
    pub status: u16,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct TlsArtifact {
    pub id: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issued_at: String,
    pub expires_at: String,
    pub auto_renew: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AdminLogRecord {
    pub ts: String,
    pub ip: String,
    pub action: String,
    pub success: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SessionInfo {
    pub token: String,
    pub username: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DashboardStats {
    pub portforward_total: usize,
    pub portforward_enabled: usize,
    pub ddns_total: usize,
    pub ddns_enabled: usize,
    pub webservice_total: usize,
    pub webservice_enabled: usize,
    pub tls_total: usize,
    pub tls_enabled: usize,
    pub ipfilter_total: usize,
    pub active_sessions: usize,
}

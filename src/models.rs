use serde::{Deserialize, Serialize};

// ─── Admin ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    pub password_hash: String,
    pub port: u16,
    #[serde(default)]
    pub safe_entry: String,
    #[serde(default)]
    pub welcome_shown: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsView {
    pub username: String,
    pub port: u16,
    pub safe_entry: String,
    pub welcome_shown: bool,
    pub version: String,
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortForwardRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortForwardStats {
    pub id: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderConf {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zone_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zerossl_api_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zerossl_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpRecord {
    pub ip: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DdnsRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub sub_domain: String,
    #[serde(default)]
    pub ip_version: String,
    #[serde(default)]
    pub ip_detect_mode: String,
    #[serde(default)]
    pub ip_interface: String,
    #[serde(default)]
    pub ip_index: i32,
    #[serde(default)]
    pub interval: i32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider_conf: ProviderConf,
    #[serde(default)]
    pub last_ip: String,
    #[serde(default)]
    pub last_updated: String,
    #[serde(default)]
    pub ip_history: Vec<IpRecord>,
    #[serde(default)]
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_sync_err: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_sync_at: String,
}

// ─── Web Service ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebServiceRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub enable_https: bool,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<WebRoute>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebRoute {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub backend_url: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub matched_cert_id: String,
    #[serde(default)]
    pub cert_status: String,
    #[serde(default)]
    pub auth_enabled: bool,
    #[serde(default)]
    pub auth_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_pass_hash: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessLog {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub service_id: String,
    #[serde(default)]
    pub route_id: String,
    #[serde(default)]
    pub route_name: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub status_code: u16,
    #[serde(default)]
    pub client_ip: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub auth_result: String,
    #[serde(default)]
    pub time: String,
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub ca_provider: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub provider_conf: ProviderConf,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_pem: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_pem: String,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub auto_renew: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_msg: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub created_at: String,
}

impl TlsRule {
    pub fn days_until_expiry(&self) -> i64 {
        if self.expires_at.is_empty() {
            return -1;
        }
        chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map(|t| {
                t.signed_duration_since(chrono::Utc::now()).num_days()
            })
            .unwrap_or(-1)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCertView {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub domains: Vec<String>,
    pub source: String,
    pub ca_provider: String,
    pub provider: String,
    pub provider_conf: ProviderConf,
    pub email: String,
    pub issued_at: String,
    pub expires_at: String,
    pub auto_renew: bool,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error_msg: String,
    pub days_left: i64,
    pub created_at: String,
    pub has_cert: bool,
    pub enabled: bool,
}

impl From<&TlsRule> for TlsCertView {
    fn from(r: &TlsRule) -> Self {
        TlsCertView {
            id: r.id.clone(),
            name: r.name.clone(),
            domain: r.domain.clone(),
            domains: r.domains.clone(),
            source: r.source.clone(),
            ca_provider: r.ca_provider.clone(),
            provider: r.provider.clone(),
            provider_conf: r.provider_conf.clone(),
            email: r.email.clone(),
            issued_at: r.issued_at.clone(),
            expires_at: r.expires_at.clone(),
            auto_renew: r.auto_renew,
            status: r.status.clone(),
            error_msg: r.error_msg.clone(),
            days_left: r.days_until_expiry(),
            created_at: r.created_at.clone(),
            has_cert: !r.cert_pem.is_empty(),
            enabled: r.enabled,
        }
    }
}

// ─── IP Filter ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterAttachment {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterScope {
    #[serde(rename = "type", default)]
    pub scope_type: String,
    #[serde(default)]
    pub target_id: String,
    #[serde(default)]
    pub target_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub scopes: Vec<IpFilterScope>,
    #[serde(default)]
    pub manual_ips: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<IpFilterAttachment>,
    #[serde(default)]
    pub created_at: String,
}

// ─── Logs / Sessions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdminLogRecord {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionInfo {
    pub token: String,
    pub username: String,
    pub created_at: String,
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Default)]
pub struct DashboardStats {
    pub port_forwards: usize,
    pub ddns: usize,
    pub web_services: usize,
    pub tls_certs: usize,
    pub certs_expiring_soon: usize,
}

// ─── RuntimeData ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeData {
    #[serde(default)]
    pub portforward: Vec<PortForwardRule>,
    #[serde(default)]
    pub ddns: Vec<DdnsRule>,
    #[serde(default)]
    pub webservice: Vec<WebServiceRule>,
    #[serde(default)]
    pub tls: Vec<TlsRule>,
    #[serde(default)]
    pub ipfilter: Vec<IpFilterRule>,
    #[serde(default)]
    pub access_logs: Vec<AccessLog>,
    #[serde(default)]
    pub admin_logs: Vec<AdminLogRecord>,
    #[serde(default)]
    pub sessions_meta: Vec<SessionInfo>,
}

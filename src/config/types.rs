use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Admin ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminConfig {
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub port: u16,
    pub safe_entry: String,
    pub welcome_shown: bool,
}

impl AdminConfig {
    pub fn check_password(&self, plain: &str) -> bool {
        bcrypt::verify(plain, &self.password_hash).unwrap_or(false)
    }

    pub fn set_password(&mut self, plain: &str) -> anyhow::Result<()> {
        self.password_hash = bcrypt::hash(plain, bcrypt::DEFAULT_COST)?;
        Ok(())
    }
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub id: String,
    pub name: String,
    pub protocol: String, // "tcp" | "udp" | "both"
    pub listen_port: u16,
    pub target_ip: String,
    pub target_port: u16,
    pub enabled: bool,
    pub created_at: String,
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsRule {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub sub_domain: String,
    pub ip_version: String, // "ipv4" | "ipv6"
    pub ip_detect_mode: String, // "api" | "iface"
    #[serde(default)]
    pub ip_interface: String,
    #[serde(default)]
    pub ip_index: i32,
    pub interval: i64, // seconds
    pub enabled: bool,
    pub provider_conf: ProviderConf,
    #[serde(default)]
    pub last_ip: String,
    #[serde(default)]
    pub last_updated: String,
    #[serde(default)]
    pub ip_history: Vec<IpRecord>,
    pub created_at: String,
    // runtime status (not persisted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_sync_err: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_sync_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConf {
    // Cloudflare DNS
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zone_id: String,
    // 其他 DNS 服务商（保留兼容）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_key: String,
    // ZeroSSL EAB（前端字段名必须与 Go 版一致）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zerossl_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zerossl_api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRecord {
    pub ip: String,
    pub timestamp: String,
}

// ─── WebService ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebService {
    pub id: String,
    pub name: String,
    pub listen_port: u16,
    pub enable_https: bool,
    pub enabled: bool,
    pub routes: Vec<WebRoute>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebRoute {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub backend_url: String,
    pub enabled: bool,
    pub matched_cert_id: String,
    pub cert_status: String, // "ok" | "no_cert" | "cert_inactive"
    pub auth_enabled: bool,
    pub auth_user: String,
    #[serde(default)]
    pub auth_pass_hash: String,
    pub created_at: String,
}

impl serde::Serialize for WebRoute {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("WebRoute", 11)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("domain", &self.domain)?;
        st.serialize_field("backend_url", &self.backend_url)?;
        st.serialize_field("enabled", &self.enabled)?;
        st.serialize_field("matched_cert_id", &self.matched_cert_id)?;
        st.serialize_field("cert_status", &self.cert_status)?;
        st.serialize_field("auth_enabled", &self.auth_enabled)?;
        st.serialize_field("auth_user", &self.auth_user)?;
        // Never expose the hash; send a simple flag so the frontend knows
        // whether a password is currently stored.
        st.serialize_field("auth_pass_set", if self.auth_pass_hash.is_empty() { "" } else { "set" })?;
        st.serialize_field("created_at", &self.created_at)?;
        st.end()
    }
}

// ─── TLS Cert ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCert {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub domain: String,
    pub source: String,     // "acme" | "upload"
    pub ca_provider: String, // "letsencrypt" | "zerossl"
    pub provider: String,   // dns provider for ACME
    pub provider_conf: ProviderConf,
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub expires_at: String,
    pub auto_renew: bool,
    pub email: String,
    pub status: String, // "pending" | "active" | "error"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_msg: String,
    pub created_at: String,
}

impl TlsCert {
    pub fn days_until_expiry(&self) -> i64 {
        if self.expires_at.is_empty() {
            return -1;
        }
        self.expires_at
            .parse::<DateTime<Utc>>()
            .map(|t| (t - Utc::now()).num_days())
            .unwrap_or(-1)
    }
}

// ─── IP Filter ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterRule {
    pub id: String,
    pub enabled: bool,
    pub mode: String, // "whitelist" | "blacklist"
    pub scopes: Vec<IpFilterScope>,
    pub manual_ips: Vec<String>,
    pub attachments: Vec<IpFilterAttachment>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterScope {
    #[serde(rename = "type")]
    pub scope_type: String, // "admin" | "portforward" | "webservice"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFilterAttachment {
    pub name: String,
    pub ips: Vec<String>,
}

// ─── Backup ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullBackup {
    pub version: String,
    pub admin: AdminConfig,
    pub port_forwards: Vec<PortForwardRule>,
    pub ddns: Vec<DdnsRule>,
    pub web_services: Vec<WebService>,
    pub tls_certs: Vec<TlsCert>,
    pub ip_filter: Vec<IpFilterRule>,
}

// ─── Utilities ────────────────────────────────────────────────────────────────

pub fn new_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(format!("0.0.0.0:{}", port)).is_ok()
}

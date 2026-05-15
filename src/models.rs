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
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DdnsRule {
    pub id: String,
    pub provider: String,
    pub domain: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebServiceRule {
    pub id: String,
    pub domain: String,
    pub backend: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsRule {
    pub id: String,
    pub domain: String,
    pub cert_path: String,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpFilterRule {
    pub id: String,
    pub target: String,
    pub cidr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeData {
    pub portforward: Vec<PortForwardRule>,
    pub ddns: Vec<DdnsRule>,
    pub webservice: Vec<WebServiceRule>,
    pub tls: Vec<TlsRule>,
    pub ipfilter: Vec<IpFilterRule>,
}

use crate::config::{
    db, Config, DdnsRule, IpRecord,
};
use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tracing::{error, info, warn};

// ─── Manager ──────────────────────────────────────────────────────────────────

pub struct Manager {
    cfg: Config,
    workers: Mutex<HashMap<String, watch::Sender<bool>>>,
}

#[derive(Debug, serde::Serialize)]
pub struct SyncResult {
    pub ip: String,
    pub ip_err: Option<String>,
    pub domains: HashMap<String, String>, // fqdn → "" (ok) or error message
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            workers: Mutex::new(HashMap::new()),
        })
    }

    pub fn start_all(self: &Arc<Self>) {
        let rules: Vec<DdnsRule> = {
            let cfg = self.cfg.read();
            cfg.ddns.iter().filter(|r| r.enabled).cloned().collect()
        };
        for rule in rules {
            self.start(&rule.id);
        }
    }

    pub fn start(self: &Arc<Self>, id: &str) {
        self.stop(id);

        let rule = {
            let cfg = self.cfg.read();
            cfg.ddns.iter().find(|r| r.id == id).cloned()
        };
        let Some(rule) = rule else { return };

        let (tx, rx) = watch::channel(false);
        self.workers.lock().unwrap().insert(id.to_string(), tx);
        let cfg = self.cfg.clone();
        tokio::spawn(async move {
            run_worker(rule, cfg, rx).await;
        });
    }

    pub fn stop(&self, id: &str) {
        if let Some(tx) = self.workers.lock().unwrap().remove(id) {
            let _ = tx.send(true);
        }
    }

    pub async fn trigger_now(self: &Arc<Self>, id: &str) -> Result<SyncResult> {
        let rule = {
            let cfg = self.cfg.read();
            cfg.ddns.iter().find(|r| r.id == id).cloned()
        };
        let rule = rule.ok_or_else(|| anyhow!("rule not found"))?;

        let mut result = SyncResult {
            ip: String::new(),
            ip_err: None,
            domains: HashMap::new(),
        };

        let ip = match get_public_ip(&rule.ip_version, &rule.ip_detect_mode, &rule.ip_interface, rule.ip_index).await {
            Ok(ip) => ip,
            Err(e) => {
                result.ip_err = Some(e.to_string());
                self.write_sync_status(&rule.id, false, &format!("IP获取失败: {}", e));
                return Ok(result);
            }
        };
        result.ip = ip.clone();

        let domains = effective_domains(&rule);
        let mut all_ok = true;
        let mut first_err = String::new();

        for fqdn in &domains {
            let update_result = match rule.provider.as_str() {
                "cloudflare" => update_cloudflare(&rule, fqdn, &ip).await,
                other => Err(anyhow!("未知的 DNS 服务商: {}", other)),
            };
            match update_result {
                Ok(_) => { result.domains.insert(fqdn.clone(), String::new()); }
                Err(e) => {
                    let msg = e.to_string();
                    if first_err.is_empty() {
                        first_err = format!("{}: {}", fqdn, msg);
                    }
                    result.domains.insert(fqdn.clone(), msg);
                    all_ok = false;
                }
            }
        }

        let now = crate::config::types::now_rfc3339();
        {
            let mut cfg = self.cfg.write();
            if let Some(r) = cfg.ddns.iter_mut().find(|r| r.id == id) {
                r.last_ip = ip.clone();
                r.last_updated = now.clone();
                r.last_sync_at = now;
                r.last_sync_ok = Some(all_ok);
                r.last_sync_err = if all_ok { String::new() } else { first_err };
                r.ip_history.push(IpRecord { ip: ip.clone(), timestamp: crate::config::types::now_rfc3339() });
                if r.ip_history.len() > 100 {
                    let len = r.ip_history.len();
                    r.ip_history.drain(0..len - 100);
                }
            }
        }
        self.persist(&id);
        Ok(result)
    }

    fn write_sync_status(&self, id: &str, ok: bool, err_msg: &str) {
        let now = crate::config::types::now_rfc3339();
        let mut cfg = self.cfg.write();
        if let Some(r) = cfg.ddns.iter_mut().find(|r| r.id == id) {
            r.last_sync_ok = Some(ok);
            r.last_sync_err = err_msg.to_string();
            r.last_sync_at = now;
        }
    }

    fn persist(&self, id: &str) {
        let rule = {
            let cfg = self.cfg.read();
            cfg.ddns.iter().find(|r| r.id == id).cloned()
        };
        let Some(rule) = rule else { return };
        let dd = {
            let cfg = self.cfg.read();
            cfg.data_dir.clone()
        };
        let Some(dd) = dd else { return };
        if let Err(e) = db::save_ddns(&dd, &rule) {
            error!("[ddns] persist {} error: {}", id, e);
        }
    }
}

async fn run_worker(rule: DdnsRule, cfg: Config, mut stop: watch::Receiver<bool>) {
    let interval_secs = rule.interval.max(60) as u64;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { break; } }
            _ = ticker.tick() => {
                // Reload rule from config (may have been updated)
                let current_rule = {
                    let c = cfg.read();
                    c.ddns.iter().find(|r| r.id == rule.id).cloned()
                };
                let Some(current_rule) = current_rule else { break };
                if !current_rule.enabled { break; }

                let ip = match get_public_ip(
                    &current_rule.ip_version,
                    &current_rule.ip_detect_mode,
                    &current_rule.ip_interface,
                    current_rule.ip_index,
                ).await {
                    Ok(ip) => ip,
                    Err(e) => {
                        error!("[ddns] {} IP detect error: {}", current_rule.id, e);
                        continue;
                    }
                };

                // Skip if unchanged
                if ip == current_rule.last_ip {
                    continue;
                }

                let domains = effective_domains(&current_rule);
                let mut all_ok = true;
                let mut first_err = String::new();

                for fqdn in &domains {
                    let r = match current_rule.provider.as_str() {
                        "cloudflare" => update_cloudflare(&current_rule, fqdn, &ip).await,
                        other => Err(anyhow!("未知的 DNS 服务商: {}", other)),
                    };
                    if let Err(e) = r {
                        if first_err.is_empty() {
                            first_err = format!("{}: {}", fqdn, e);
                        }
                        all_ok = false;
                    }
                }

                let now = crate::config::types::now_rfc3339();
                {
                    let mut c = cfg.write();
                    if let Some(r) = c.ddns.iter_mut().find(|r| r.id == current_rule.id) {
                        r.last_ip = ip.clone();
                        r.last_updated = now.clone();
                        r.last_sync_at = now;
                        r.last_sync_ok = Some(all_ok);
                        r.last_sync_err = if all_ok { String::new() } else { first_err };
                        r.ip_history.push(IpRecord { ip, timestamp: crate::config::types::now_rfc3339() });
                        if r.ip_history.len() > 100 {
                            let len = r.ip_history.len();
                            r.ip_history.drain(0..len - 100);
                        }
                    }
                }

                let dd = cfg.read().data_dir.clone();
                if let Some(dd) = dd {
                    let rule_snap = cfg.read().ddns.iter().find(|r| r.id == current_rule.id).cloned();
                    if let Some(rule_snap) = rule_snap {
                        let _ = db::save_ddns(&dd, &rule_snap);
                    }
                }
            }
        }
    }
}

fn effective_domains(rule: &DdnsRule) -> Vec<String> {
    if !rule.domains.is_empty() {
        return rule.domains.clone();
    }
    if !rule.domain.is_empty() {
        let fqdn = if rule.sub_domain.is_empty() || rule.sub_domain == "@" {
            rule.domain.clone()
        } else {
            format!("{}.{}", rule.sub_domain, rule.domain)
        };
        return vec![fqdn];
    }
    vec![]
}

// ─── Public IP detection ──────────────────────────────────────────────────────

pub async fn get_public_ip(version: &str, mode: &str, iface: &str, ip_index: i32) -> Result<String> {
    if mode == "iface" && !iface.is_empty() {
        return get_ip_from_interface(iface, version, ip_index);
    }
    get_public_ip_via_api(version).await
}

async fn get_public_ip_via_api(version: &str) -> Result<String> {
    let (urls, is_v6) = if version == "ipv6" {
        (vec![
            "https://ipv6.icanhazip.com",
            "https://api6.ipify.org",
            "https://v6.ident.me",
        ], true)
    } else {
        (vec![
            "https://ipv4.icanhazip.com",
            "https://api4.ipify.org",
            "https://v4.ident.me",
            "https://4.ipw.cn",
        ], false)
    };

    let ipv4_re = Regex::new(r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])").unwrap();
    let ipv6_re = Regex::new(r"(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|:(:[0-9A-Fa-f]{1,4}){1,7})").unwrap();
    let re = if is_v6 { &ipv6_re } else { &ipv4_re };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    for url in &urls {
        match client.get(*url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    if let Some(m) = re.find(&body) {
                        let ip = m.as_str().to_string();
                        info!("[ddns] got {} from {}: {}", version, url, ip);
                        return Ok(ip);
                    }
                }
            }
            Err(e) => { warn!("[ddns] API {} failed: {}", url, e); }
        }
    }
    Err(anyhow!("all {} IP detection endpoints failed", version))
}

fn get_ip_from_interface(iface_name: &str, version: &str, ip_index: i32) -> Result<String> {
    use std::net::IpAddr;
    let ifaces = nix_ifaces()?;
    let want_v6 = version == "ipv6";
    let mut candidates = Vec::new();
    let mut private_found = Vec::new();

    for (name, addrs) in &ifaces {
        if name != iface_name { continue; }
        for addr in addrs {
            let is_v6 = matches!(addr, IpAddr::V6(_));
            if is_v6 != want_v6 { continue; }
            match addr {
                IpAddr::V4(v4) => {
                    if v4.is_loopback() || v4.is_link_local() { continue; }
                    if v4.is_private() { private_found.push(addr.to_string()); continue; }
                    candidates.push(addr.to_string());
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_multicast() { continue; }
                    // skip ULA (fc00::/7)
                    let first = v6.octets()[0];
                    if first & 0xfe == 0xfc { continue; }
                    candidates.push(addr.to_string());
                }
            }
        }
    }

    if candidates.is_empty() {
        if !private_found.is_empty() {
            return Err(anyhow!("网卡 {} 上未检测到公网IP（当前地址 {} 为内网地址）", iface_name, private_found.join(", ")));
        }
        return Err(anyhow!("网卡 {} 上未找到可用的 {} 地址", iface_name, version));
    }

    let idx = (ip_index as usize).min(candidates.len() - 1);
    Ok(candidates[idx].clone())
}

// Minimal interface IP reader using /proc/net or std::net
fn nix_ifaces() -> Result<HashMap<String, Vec<std::net::IpAddr>>> {
    let mut map: HashMap<String, Vec<std::net::IpAddr>> = HashMap::new();
    for iface in pnet_datalink::interfaces() {
        let ips: Vec<std::net::IpAddr> = iface.ips.iter().map(|n| n.ip()).collect();
        map.insert(iface.name, ips);
    }
    Ok(map)
}

pub fn get_interfaces() -> Vec<String> {
    pnet_datalink::interfaces()
        .into_iter()
        .filter(|i| {
            !i.is_loopback() && {
                // Linux: check /sys/class/net/<name>/device
                let dev = format!("/sys/class/net/{}/device", i.name);
                let wifi = format!("/sys/class/net/{}/wireless", i.name);
                std::path::Path::new(&dev).exists() || std::path::Path::new(&wifi).exists()
            }
        })
        .map(|i| i.name)
        .collect()
}

pub async fn list_iface_ips(iface_name: &str, version: &str) -> Vec<String> {
    use std::net::IpAddr;
    let want_v6 = version == "ipv6";
    let mut result = Vec::new();

    for iface in pnet_datalink::interfaces() {
        if iface.name != iface_name { continue; }
        for ip_net in &iface.ips {
            let ip = ip_net.ip();
            let is_v6 = matches!(ip, IpAddr::V6(_));
            if is_v6 != want_v6 { continue; }
            match ip {
                IpAddr::V4(v4) if v4.is_loopback() || v4.is_link_local() || v4.is_private() => continue,
                IpAddr::V6(v6) if v6.is_loopback() || (v6.octets()[0] & 0xfe == 0xfc) => continue,
                _ => result.push(ip.to_string()),
            }
        }
        break;
    }
    result
}

// ─── Cloudflare DDNS ──────────────────────────────────────────────────────────

async fn cf_resolve_zone_id(client: &reqwest::Client, token: &str, zone_id_hint: &str, fqdn: &str) -> Result<String> {
    if !zone_id_hint.is_empty() {
        return Ok(zone_id_hint.to_string());
    }
    let resp = client
        .get("https://api.cloudflare.com/client/v4/zones?per_page=100")
        .bearer_auth(token)
        .send().await?
        .json::<serde_json::Value>().await?;

    let zones = resp["result"].as_array().ok_or_else(|| anyhow!("cloudflare: no result"))?;
    let zone_map: HashMap<String, String> = zones.iter().filter_map(|z| {
        Some((z["name"].as_str()?.to_string(), z["id"].as_str()?.to_string()))
    }).collect();

    let parts: Vec<&str> = fqdn.split('.').collect();
    for n in 2..=parts.len().min(20) {
        let candidate = parts[parts.len() - n..].join(".");
        if let Some(id) = zone_map.get(&candidate) {
            return Ok(id.clone());
        }
    }
    Err(anyhow!("cloudflare: no zone found for domain {}", fqdn))
}

async fn update_cloudflare(rule: &DdnsRule, fqdn: &str, ip: &str) -> Result<()> {
    let token = &rule.provider_conf.api_token;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let zone_id = cf_resolve_zone_id(&client, token, &rule.provider_conf.zone_id, fqdn).await?;
    let rec_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    // Find existing record
    let list_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type={}&name={}",
        zone_id, rec_type, fqdn
    );
    let list_resp = client.get(&list_url).bearer_auth(token).send().await?.json::<serde_json::Value>().await?;
    let result = list_resp["result"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);

    let body = serde_json::json!({
        "type": rec_type,
        "name": fqdn,
        "content": ip,
        "ttl": 60,
        "proxied": false
    }).to_string();

    if let Some(rec) = result.first() {
        let record_id = rec["id"].as_str().ok_or_else(|| anyhow!("no record id"))?;
        let put_url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id);
        cf_do(&client, "PUT", &put_url, token, &body).await
    } else {
        let post_url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id);
        cf_do(&client, "POST", &post_url, token, &body).await
    }
}

async fn cf_do(client: &reqwest::Client, method: &str, url: &str, token: &str, body: &str) -> Result<()> {
    let req = match method {
        "PUT" => client.put(url),
        _ => client.post(url),
    };
    let resp = req
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send().await?
        .json::<serde_json::Value>().await?;

    if resp["success"].as_bool() == Some(true) {
        return Ok(());
    }
    let msg = resp["errors"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["message"].as_str())
        .unwrap_or("unknown error");
    Err(anyhow!("cloudflare API error: {}", msg))
}

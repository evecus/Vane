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
                "alidns" => update_alidns(&rule, fqdn, &ip).await,
                "dnspod" => update_dnspod(&rule, fqdn, &ip).await,
                "tencentcloud" => update_tencentcloud(&rule, fqdn, &ip).await,
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
                        "alidns" => update_alidns(&current_rule, fqdn, &ip).await,
                        "dnspod" => update_dnspod(&current_rule, fqdn, &ip).await,
                        "tencentcloud" => update_tencentcloud(&current_rule, fqdn, &ip).await,
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

// ─── AliDNS ───────────────────────────────────────────────────────────────────
//
// 阿里云公共 DNS API 2015-01-09
// 文档: https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-overview
// 认证: HMAC-SHA1，参数签名方式（RPC 风格）

/// 从 FQDN 中拆出 (RR, DomainName)。
/// 例: "sub.example.com" → ("sub", "example.com")
///      "example.com"    → ("@",   "example.com")
fn split_rr(fqdn: &str) -> (String, String) {
    if let Some(pos) = fqdn.find('.') {
        let rr = &fqdn[..pos];
        let domain = &fqdn[pos + 1..];
        // 如果 domain 还有点（说明 rr 部分正确），返回拆分结果
        if domain.contains('.') {
            return (rr.to_string(), domain.to_string());
        }
    }
    // 只有两段（如 example.com），RR 为 @
    ("@".to_string(), fqdn.to_string())
}

fn alidns_sign(key_secret: &str, string_to_sign: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let signing_key = format!("{}&", key_secret);
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn alidns_encode(s: &str) -> String {
    // 阿里云要求的百分号编码：比标准 URL 编码更严格（/ 也需转义）
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn alidns_call(
    client: &reqwest::Client,
    key_id: &str,
    key_secret: &str,
    action: &str,
    mut params: Vec<(&str, String)>,
) -> Result<serde_json::Value> {
    use rand::RngCore;
    use chrono::Utc;

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut nonce_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    params.push(("Action", action.to_string()));
    params.push(("Format", "JSON".to_string()));
    params.push(("Version", "2015-01-09".to_string()));
    params.push(("AccessKeyId", key_id.to_string()));
    params.push(("SignatureMethod", "HMAC-SHA1".to_string()));
    params.push(("Timestamp", timestamp));
    params.push(("SignatureVersion", "1.0".to_string()));
    params.push(("SignatureNonce", nonce));

    // 按参数名 ASCII 升序排列
    params.sort_by(|a, b| a.0.cmp(b.0));

    // 构造待签字符串
    let query_str: String = params.iter()
        .map(|(k, v)| format!("{}={}", alidns_encode(k), alidns_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("GET&{}&{}", alidns_encode("/"), alidns_encode(&query_str));
    let signature = alidns_sign(key_secret, &string_to_sign);

    let url = format!(
        "https://alidns.aliyuncs.com/?{}&Signature={}",
        query_str,
        alidns_encode(&signature),
    );

    let resp = client.get(&url).send().await?.json::<serde_json::Value>().await?;
    if let Some(code) = resp.get("Code").and_then(|v| v.as_str()) {
        if code != "OK" {
            let msg = resp["Message"].as_str().unwrap_or(code);
            return Err(anyhow!("alidns error: {}", msg));
        }
    }
    Ok(resp)
}

async fn update_alidns(rule: &DdnsRule, fqdn: &str, ip: &str) -> Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    if key_id.is_empty() || key_secret.is_empty() {
        return Err(anyhow!("alidns: AccessKeyId / AccessKeySecret 不能为空"));
    }

    let rec_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };
    let (rr, domain) = split_rr(fqdn);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // 查询现有记录
    let list_resp = alidns_call(&client, key_id, key_secret, "DescribeDomainRecords", vec![
        ("DomainName", domain.clone()),
        ("RRKeyWord", rr.clone()),
        ("Type", rec_type.to_string()),
        ("PageSize", "10".to_string()),
    ]).await?;

    let records = list_resp["DomainRecords"]["Record"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // 找到精确匹配的记录
    let existing = records.iter().find(|r| {
        r["RR"].as_str() == Some(&rr) && r["Type"].as_str() == Some(rec_type)
    });

    if let Some(rec) = existing {
        let record_id = rec["RecordId"].as_str().unwrap_or("").to_string();
        let current_value = rec["Value"].as_str().unwrap_or("");
        if current_value == ip {
            info!("[ddns] alidns {} already up to date: {}", fqdn, ip);
            return Ok(());
        }
        // 更新
        alidns_call(&client, key_id, key_secret, "UpdateDomainRecord", vec![
            ("RecordId", record_id),
            ("RR", rr),
            ("Type", rec_type.to_string()),
            ("Value", ip.to_string()),
            ("TTL", "600".to_string()),
        ]).await?;
    } else {
        // 新增
        alidns_call(&client, key_id, key_secret, "AddDomainRecord", vec![
            ("DomainName", domain),
            ("RR", rr),
            ("Type", rec_type.to_string()),
            ("Value", ip.to_string()),
            ("TTL", "600".to_string()),
        ]).await?;
    }

    info!("[ddns] alidns updated {} → {}", fqdn, ip);
    Ok(())
}

// ─── DNSPod（旧版 dnspod.cn API）─────────────────────────────────────────────
//
// 文档: https://docs.dnspod.cn/api/
// 认证: POST 表单，login_token = "SecretId,SecretKey"

async fn dnspod_call(
    client: &reqwest::Client,
    secret_id: &str,
    secret_key: &str,
    endpoint: &str,
    mut form: Vec<(&'static str, String)>,
) -> Result<serde_json::Value> {
    let login_token = format!("{},{}", secret_id, secret_key);
    form.push(("login_token", login_token));
    form.push(("format", "json".to_string()));
    form.push(("lang", "cn".to_string()));

    let url = format!("https://dnsapi.cn/{}", endpoint);
    let resp = client.post(&url)
        .form(&form)
        .send().await?
        .json::<serde_json::Value>().await?;

    let code = resp["status"]["code"].as_str().unwrap_or("0");
    if code != "1" {
        let msg = resp["status"]["message"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("dnspod error {}: {}", code, msg));
    }
    Ok(resp)
}

async fn update_dnspod(rule: &DdnsRule, fqdn: &str, ip: &str) -> Result<()> {
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    if secret_id.is_empty() || secret_key.is_empty() {
        return Err(anyhow!("dnspod: SecretId / SecretKey 不能为空"));
    }

    let rec_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };
    let (sub_domain, domain) = split_rr(fqdn);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("vane-ddns/2.0 (admin@example.com)")
        .build()?;

    // 查询记录列表
    let list_resp = dnspod_call(&client, secret_id, secret_key, "Record.List", vec![
        ("domain", domain.clone()),
        ("sub_domain", sub_domain.clone()),
        ("record_type", rec_type.to_string()),
    ]).await?;

    let records = list_resp["records"].as_array().cloned().unwrap_or_default();
    let existing = records.iter().find(|r| {
        r["name"].as_str() == Some(&sub_domain) && r["type"].as_str() == Some(rec_type)
    });

    if let Some(rec) = existing {
        let record_id = rec["id"].as_str().unwrap_or("").to_string();
        let current_value = rec["value"].as_str().unwrap_or("");
        if current_value == ip {
            info!("[ddns] dnspod {} already up to date: {}", fqdn, ip);
            return Ok(());
        }
        // 修改
        dnspod_call(&client, secret_id, secret_key, "Record.Modify", vec![
            ("domain", domain),
            ("record_id", record_id),
            ("sub_domain", sub_domain),
            ("record_type", rec_type.to_string()),
            ("value", ip.to_string()),
            ("record_line", "默认".to_string()),
            ("ttl", "600".to_string()),
        ]).await?;
    } else {
        // 新增
        dnspod_call(&client, secret_id, secret_key, "Record.Create", vec![
            ("domain", domain),
            ("sub_domain", sub_domain),
            ("record_type", rec_type.to_string()),
            ("value", ip.to_string()),
            ("record_line", "默认".to_string()),
            ("ttl", "600".to_string()),
        ]).await?;
    }

    info!("[ddns] dnspod updated {} → {}", fqdn, ip);
    Ok(())
}

// ─── TencentCloud DNS（新版 TC3-HMAC-SHA256 签名）────────────────────────────
//
// 文档: https://cloud.tencent.com/document/product/1427/56166
// Service: dnspod  Host: dnspod.tencentcloudapi.com

fn tc3_sign(
    secret_key: &str,
    date: &str,       // "2024-01-02"
    service: &str,    // "dnspod"
    string_to_sign: &str,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let sign_date = {
        let mut m = HmacSha256::new_from_slice(
            format!("TC3{}", secret_key).as_bytes()
        ).unwrap();
        m.update(date.as_bytes());
        m.finalize().into_bytes()
    };
    let sign_service = {
        let mut m = HmacSha256::new_from_slice(&sign_date).unwrap();
        m.update(service.as_bytes());
        m.finalize().into_bytes()
    };
    let sign_request = {
        let mut m = HmacSha256::new_from_slice(&sign_service).unwrap();
        m.update(b"tc3_request");
        m.finalize().into_bytes()
    };
    let mut mac = HmacSha256::new_from_slice(&sign_request).unwrap();
    mac.update(string_to_sign.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

async fn tc3_call(
    client: &reqwest::Client,
    secret_id: &str,
    secret_key: &str,
    action: &str,
    body: &str,
) -> Result<serde_json::Value> {
    use sha2::{Digest, Sha256};
    use chrono::Utc;

    let service = "dnspod";
    let host = "dnspod.tencentcloudapi.com";
    let endpoint = format!("https://{}", host);
    let now = Utc::now();
    let timestamp = now.timestamp().to_string();
    let date = now.format("%Y-%m-%d").to_string();

    // Step 1: canonical request
    let hashed_body = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_headers = format!(
        "content-type:application/json\nhost:{}\nx-tc-action:{}\n",
        host,
        action.to_lowercase()
    );
    let signed_headers = "content-type;host;x-tc-action";
    let canonical_request = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, hashed_body
    );

    // Step 2: string to sign
    let credential_scope = format!("{}/{}/tc3_request", date, service);
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, credential_scope, hashed_canonical
    );

    // Step 3: signature
    let signature = tc3_sign(secret_key, &date, service, &string_to_sign);

    // Step 4: authorization header
    let authorization = format!(
        "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        secret_id, credential_scope, signed_headers, signature
    );

    let resp = client.post(&endpoint)
        .header("Authorization", authorization)
        .header("Content-Type", "application/json")
        .header("Host", host)
        .header("X-TC-Action", action)
        .header("X-TC-Timestamp", &timestamp)
        .header("X-TC-Version", "2021-03-23")
        .body(body.to_string())
        .send().await?
        .json::<serde_json::Value>().await?;

    if let Some(err) = resp.get("Response").and_then(|r| r.get("Error")) {
        let code = err["Code"].as_str().unwrap_or("Unknown");
        let msg = err["Message"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("tencentcloud dns error {}: {}", code, msg));
    }
    Ok(resp["Response"].clone())
}

async fn update_tencentcloud(rule: &DdnsRule, fqdn: &str, ip: &str) -> Result<()> {
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    if secret_id.is_empty() || secret_key.is_empty() {
        return Err(anyhow!("tencentcloud: SecretId / SecretKey 不能为空"));
    }

    let rec_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };
    let (sub_domain, domain) = split_rr(fqdn);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // 查询记录列表
    let list_body = serde_json::json!({
        "Domain": domain,
        "Subdomain": sub_domain,
        "RecordType": rec_type,
        "Limit": 10,
    }).to_string();

    let list_resp = tc3_call(&client, secret_id, secret_key, "DescribeRecordList", &list_body).await;

    // DescribeRecordList 如果没有记录会返回 error InvalidParameter.RecordListEmpty，这是正常的
    let existing_id: Option<u64> = match &list_resp {
        Ok(resp) => {
            resp["RecordList"].as_array()
                .and_then(|arr| {
                    arr.iter().find(|r| {
                        r["Name"].as_str() == Some(&sub_domain)
                        && r["Type"].as_str() == Some(rec_type)
                    })
                })
                .and_then(|r| r["RecordId"].as_u64())
        }
        Err(_) => None,
    };

    // 检查当前值是否已经是目标 IP（避免无谓写入）
    if let Ok(ref resp) = list_resp {
        if let Some(arr) = resp["RecordList"].as_array() {
            if let Some(rec) = arr.iter().find(|r| {
                r["Name"].as_str() == Some(&sub_domain)
                && r["Type"].as_str() == Some(rec_type)
            }) {
                if rec["Value"].as_str() == Some(ip) {
                    info!("[ddns] tencentcloud {} already up to date: {}", fqdn, ip);
                    return Ok(());
                }
            }
        }
    }

    if let Some(record_id) = existing_id {
        // 修改记录
        let body = serde_json::json!({
            "Domain": domain,
            "SubDomain": sub_domain,
            "RecordType": rec_type,
            "RecordLine": "默认",
            "Value": ip,
            "RecordId": record_id,
            "TTL": 600,
        }).to_string();
        tc3_call(&client, secret_id, secret_key, "ModifyRecord", &body).await?;
    } else {
        // 新增记录
        let body = serde_json::json!({
            "Domain": domain,
            "SubDomain": sub_domain,
            "RecordType": rec_type,
            "RecordLine": "默认",
            "Value": ip,
            "TTL": 600,
        }).to_string();
        tc3_call(&client, secret_id, secret_key, "CreateRecord", &body).await?;
    }

    info!("[ddns] tencentcloud updated {} → {}", fqdn, ip);
    Ok(())
}

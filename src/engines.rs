//! Runtime engine management: port-forward, DDNS, web-service, TLS auto-renew.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use reqwest::Client;
use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, RwLock},
    time,
};

use crate::models::{
    AdminConfig, Config, DdnsRule, IpRecord, PortForwardRule, TlsRule, WebRoute, WebServiceRule,
};
use crate::state::now_rfc3339;

// ─── RuntimeEngines ──────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct RuntimeEngines {
    pub portforward: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub ddns:        Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub webservice:  Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub tls:         Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
}

impl RuntimeEngines {
    pub async fn apply_portforwards(&self, rules: &[PortForwardRule]) {
        reconcile_spawn(
            &self.portforward,
            rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
            |r, rx| { tokio::spawn(run_forwarder(r, rx)); },
        )
        .await;
    }

    pub async fn apply_ddns(
        &self,
        rules: &[DdnsRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
    ) {
        reconcile_spawn(
            &self.ddns,
            rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
            move |r, rx| {
                let data = data.clone();
                tokio::spawn(run_ddns(r, rx, data));
            },
        )
        .await;
    }

    pub async fn apply_webservice(
        &self,
        rules: &[WebServiceRule],
        tls_rules: &[TlsRule],
    ) {
        let tls_rules = tls_rules.to_vec();
        reconcile_spawn(
            &self.webservice,
            rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
            move |r, rx| {
                let tls = tls_rules.clone();
                tokio::spawn(run_webservice(r, rx, tls));
            },
        )
        .await;
    }

    pub async fn apply_tls(
        &self,
        rules: &[TlsRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
        _cfg: Config,
    ) {
        reconcile_spawn(
            &self.tls,
            rules.iter().filter(|r| r.enabled && r.auto_renew).map(|r| (r.id.clone(), r.clone())).collect(),
            move |r, rx| {
                let data = data.clone();
                tokio::spawn(run_tls_autorenew(r, rx, data));
            },
        )
        .await;
    }
}

async fn reconcile_spawn<T: Clone + Send + 'static>(
    map: &Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    enabled: Vec<(String, T)>,
    spawn: impl Fn(T, oneshot::Receiver<()>) + Copy,
) {
    let ids: std::collections::HashSet<_> = enabled.iter().map(|(id, _)| id.clone()).collect();
    {
        let mut m = map.write().await;
        let to_stop: Vec<String> = m.keys().filter(|k| !ids.contains(*k)).cloned().collect();
        for id in to_stop {
            if let Some(tx) = m.remove(&id) {
                let _ = tx.send(());
            }
        }
    }
    for (id, r) in enabled {
        let mut m = map.write().await;
        if m.contains_key(&id) {
            continue; // already running
        }
        let (tx, rx) = oneshot::channel();
        m.insert(id, tx);
        spawn(r, rx);
    }
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

async fn run_forwarder(rule: PortForwardRule, mut stop: oneshot::Receiver<()>) {
    let listen_addr = rule.effective_listen_addr();
    let target_addr = rule.effective_target_addr();

    if target_addr.is_empty() {
        eprintln!("[portforward] {} has no target configured", rule.id);
        return;
    }

    let listen: SocketAddr = match listen_addr.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] invalid listen addr {:?}: {e}", listen_addr);
            return;
        }
    };
    let target: SocketAddr = match target_addr.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] invalid target addr {:?}: {e}", target_addr);
            return;
        }
    };

    let proto = rule.protocol.to_lowercase();
    if proto == "udp" {
        run_udp_forwarder(listen, target, stop).await;
        return;
    }

    // Default to TCP
    let listener = match TcpListener::bind(listen).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] bind {listen} failed: {e}");
            return;
        }
    };
    eprintln!("[portforward] {} {proto} {listen} -> {target}", rule.id);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            c = listener.accept() => {
                if let Ok((inbound, _)) = c {
                    tokio::spawn(proxy_tcp(inbound, target));
                }
            }
        }
    }
    eprintln!("[portforward] {} stopped", rule.id);
}

async fn proxy_tcp(mut inbound: TcpStream, target: SocketAddr) {
    if let Ok(mut outbound) = TcpStream::connect(target).await {
        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
    }
}

async fn run_udp_forwarder(
    listen: SocketAddr,
    target: SocketAddr,
    mut stop: oneshot::Receiver<()>,
) {
    let inbound = match UdpSocket::bind(listen).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("[udp_forward] bind {listen} failed: {e}");
            return;
        }
    };

    let nat: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut stop => break,
            r = inbound.recv_from(&mut buf) => {
                let (n, client) = match r { Ok(x) => x, Err(_) => continue };
                let data = buf[..n].to_vec();

                let outbound = {
                    let r = nat.read().await;
                    r.get(&client).cloned()
                };
                let outbound = match outbound {
                    Some(s) => s,
                    None => {
                        let s = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => Arc::new(s),
                            Err(_) => continue,
                        };
                        nat.write().await.insert(client, s.clone());

                        let s2 = s.clone();
                        let inbound2 = inbound.clone();
                        let nat2 = nat.clone();
                        tokio::spawn(async move {
                            let mut rbuf = vec![0u8; 65535];
                            loop {
                                match s2.recv_from(&mut rbuf).await {
                                    Ok((rn, _src)) => {
                                        let _ = inbound2.send_to(&rbuf[..rn], client).await;
                                    }
                                    Err(_) => break,
                                }
                                if !nat2.read().await.contains_key(&client) {
                                    break;
                                }
                            }
                        });
                        s
                    }
                };
                let _ = outbound.send_to(&data, target).await;
            }
        }
    }
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

async fn run_ddns(
    rule: DdnsRule,
    mut stop: oneshot::Receiver<()>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
) {
    let client = Client::new();
    // Run once immediately
    sync_and_record(&client, &rule, &data).await;

    let interval_secs = if rule.interval > 0 { rule.interval as u64 } else { 300 };
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(interval_secs)) => {
                sync_and_record(&client, &rule, &data).await;
            }
        }
    }
}

async fn sync_and_record(
    client: &Client,
    rule: &DdnsRule,
    data: &Arc<RwLock<crate::models::RuntimeData>>,
) {
    let result = sync_ddns_provider(client, rule).await;
    let at = now_rfc3339();
    let mut d = data.write().await;
    if let Some(r) = d.ddns.iter_mut().find(|x| x.id == rule.id) {
        match &result {
            Ok(ip) => {
                r.last_ip = ip.clone();
                r.last_updated = at.clone();
                r.last_sync_ok = Some(true);
                r.last_sync_err.clear();
                r.last_sync_at = at.clone();
                r.ip_history.push(IpRecord { ip: ip.clone(), timestamp: at });
                if r.ip_history.len() > 100 {
                    let n = r.ip_history.len() - 100;
                    r.ip_history.drain(0..n);
                }
            }
            Err(e) => {
                r.last_sync_ok = Some(false);
                r.last_sync_err = e.to_string();
                r.last_sync_at = at;
            }
        }
    }
}

pub async fn sync_ddns_provider(client: &Client, rule: &DdnsRule) -> anyhow::Result<String> {
    let ip = if rule.ip_detect_mode == "interface" && !rule.ip_interface.is_empty() {
        get_interface_ip(&rule.ip_interface, &rule.ip_version, rule.ip_index)
            .ok_or_else(|| anyhow::anyhow!("no IP found on interface {}", rule.ip_interface))?
    } else {
        get_public_ip(client, &rule.ip_version).await?
    };

    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => sync_cloudflare(client, rule, &ip).await?,
        "alidns" | "aliyun" => sync_alidns(client, rule, &ip).await?,
        "dnspod" => sync_dnspod(client, rule, &ip).await?,
        "tencent" | "tencentcloud" => sync_tencent(client, rule, &ip).await?,
        p => eprintln!("[ddns] unknown provider {p:?}"),
    }
    Ok(ip)
}

async fn get_public_ip(client: &Client, ip_version: &str) -> anyhow::Result<String> {
    let urls: &[&str] = if ip_version == "ipv6" {
        &["https://api6.ipify.org", "https://v6.ident.me"]
    } else {
        &["https://api.ipify.org", "https://ident.me", "https://api4.ipify.org"]
    };
    let mut last_err = anyhow::anyhow!("no IP source available");
    for url in urls {
        match client.get(*url).timeout(Duration::from_secs(10)).send().await {
            Ok(r) => {
                if let Ok(t) = r.text().await {
                    let ip = t.trim().to_string();
                    if !ip.is_empty() { return Ok(ip); }
                }
            }
            Err(e) => last_err = e.into(),
        }
    }
    Err(last_err)
}

fn get_interface_ip(iface: &str, ip_version: &str, index: i32) -> Option<String> {
    let ips = crate::handlers::collect_iface_ips(iface, ip_version);
    let idx = if index < 0 { 0 } else { index as usize };
    ips.get(idx).cloned()
}

async fn sync_cloudflare(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;
    if token.is_empty() || zone.is_empty() {
        return Err(anyhow::anyhow!("Cloudflare requires api_token and zone_id"));
    }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    for fqdn in domains {
        let recs: serde_json::Value = client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type={record_type}&name={fqdn}"
            ))
            .bearer_auth(token)
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .json()
            .await?;

        if let Some(rid) = recs["result"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|x| x["id"].as_str())
        {
            client
                .put(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rid}"
                ))
                .bearer_auth(token)
                .timeout(Duration::from_secs(15))
                .json(&serde_json::json!({"type": record_type, "name": fqdn, "content": ip, "proxied": false}))
                .send()
                .await?;
        } else {
            client
                .post(format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"))
                .bearer_auth(token)
                .timeout(Duration::from_secs(15))
                .json(&serde_json::json!({"type": record_type, "name": fqdn, "content": ip, "proxied": false}))
                .send()
                .await?;
        }
    }
    Ok(())
}

async fn sync_alidns(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    if key_id.is_empty() || key_secret.is_empty() {
        return Err(anyhow::anyhow!("AliDNS requires access_key_id and access_key_secret"));
    }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (rr, domain) = if parts.len() == 2 { (parts[0], parts[1]) } else { ("@", fqdn.as_str()) };

        let describe_params = build_aliyun_params(key_id, "DescribeDomainRecords", &[
            ("DomainName", domain), ("RRKeyWord", rr), ("TypeKeyWord", record_type),
        ]);

        let resp: serde_json::Value = client
            .get("https://alidns.aliyuncs.com/")
            .query(&sign_aliyun_params(&describe_params, key_secret))
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .json()
            .await?;

        let record_id = resp["DomainRecords"]["Record"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r["RecordId"].as_str())
            .map(|s| s.to_string());

        if let Some(rid) = record_id {
            let update_params = build_aliyun_params(key_id, "UpdateDomainRecord", &[
                ("RecordId", rid.as_str()), ("RR", rr), ("Type", record_type), ("Value", ip),
            ]);
            client.get("https://alidns.aliyuncs.com/")
                .query(&sign_aliyun_params(&update_params, key_secret))
                .timeout(Duration::from_secs(15)).send().await?;
        } else {
            let add_params = build_aliyun_params(key_id, "AddDomainRecord", &[
                ("DomainName", domain), ("RR", rr), ("Type", record_type), ("Value", ip),
            ]);
            client.get("https://alidns.aliyuncs.com/")
                .query(&sign_aliyun_params(&add_params, key_secret))
                .timeout(Duration::from_secs(15)).send().await?;
        }
    }
    Ok(())
}

fn build_aliyun_params<'a>(key_id: &'a str, action: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(String, String)> {
    let nonce = {
        use rand_core::RngCore;
        let mut buf = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    };
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut params: Vec<(String, String)> = vec![
        ("Action".into(), action.into()),
        ("AccessKeyId".into(), key_id.into()),
        ("Format".into(), "JSON".into()),
        ("SignatureMethod".into(), "HMAC-SHA1".into()),
        ("SignatureNonce".into(), nonce),
        ("SignatureVersion".into(), "1.0".into()),
        ("Timestamp".into(), timestamp),
        ("Version".into(), "2015-01-09".into()),
    ];
    for (k, v) in extra { params.push((k.to_string(), v.to_string())); }
    params
}

fn sign_aliyun_params(params: &[(String, String)], secret: &str) -> Vec<(String, String)> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let query_str: String = sorted.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>().join("&");

    let string_to_sign = format!("GET&{}&{}", urlencoding::encode("/"), urlencoding::encode(&query_str));

    let key = format!("{secret}&");
    let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).expect("HMAC init");
    mac.update(string_to_sign.as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let mut result = sorted;
    result.push(("Signature".into(), sig));
    result
}

async fn sync_dnspod(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    if token.is_empty() { return Err(anyhow::anyhow!("DNSPod requires api_token")); }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (sub, domain) = if parts.len() == 2 { (parts[0], parts[1]) } else { ("@", fqdn.as_str()) };

        let list: serde_json::Value = client
            .post("https://dnsapi.cn/Record.List")
            .form(&[("login_token", token.as_str()), ("format", "json"), ("domain", domain), ("sub_domain", sub)])
            .timeout(Duration::from_secs(15)).send().await?.json().await?;

        let record_id = list["records"].as_array()
            .and_then(|a| a.iter().find(|r| r["type"].as_str().map(|t| t == record_type).unwrap_or(false)))
            .and_then(|r| r["id"].as_str())
            .map(|s| s.to_string());

        if let Some(rid) = record_id {
            client.post("https://dnsapi.cn/Record.Modify")
                .form(&[("login_token", token.as_str()), ("format", "json"), ("domain", domain),
                        ("record_id", rid.as_str()), ("sub_domain", sub), ("record_type", record_type),
                        ("value", ip), ("record_line", "默认")])
                .timeout(Duration::from_secs(15)).send().await?;
        } else {
            client.post("https://dnsapi.cn/Record.Create")
                .form(&[("login_token", token.as_str()), ("format", "json"), ("domain", domain),
                        ("sub_domain", sub), ("record_type", record_type), ("value", ip), ("record_line", "默认")])
                .timeout(Duration::from_secs(15)).send().await?;
        }
    }
    Ok(())
}

async fn sync_tencent(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    if secret_id.is_empty() || secret_key.is_empty() {
        return Err(anyhow::anyhow!("Tencent DNS requires secret_id and secret_key"));
    }
    let token = format!("{secret_id},{secret_key}");
    let mut proxy_rule = rule.clone();
    proxy_rule.provider_conf.api_token = token;
    sync_dnspod(client, &proxy_rule, ip).await
}

pub fn effective_domains(rule: &DdnsRule) -> Vec<String> {
    if !rule.domains.is_empty() { return rule.domains.clone(); }
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

// ─── Web Service (HTTP reverse proxy with optional TLS) ───────────────────────

/// Find the best matching TLS certificate for a domain, supporting wildcards.
pub fn find_tls_cert<'a>(tls_rules: &'a [TlsRule], domain: &str) -> Option<&'a TlsRule> {
    // Prefer active exact match, then active wildcard, then inactive
    let mut best: Option<&TlsRule> = None;
    for cert in tls_rules {
        if cert.cert_pem.is_empty() || cert.key_pem.is_empty() { continue; }
        let all_domains: Vec<&str> = cert.domains.iter().map(|s| s.as_str())
            .chain(if cert.domain.is_empty() { None } else { Some(cert.domain.as_str()) })
            .collect();
        let matched = all_domains.iter().any(|cd| cert_domain_matches(cd, domain));
        if !matched { continue; }
        match (&best, cert.status.as_str()) {
            (None, _) => best = Some(cert),
            (Some(b), "active") if b.status != "active" => best = Some(cert),
            _ => {}
        }
        if best.map(|b| b.status == "active").unwrap_or(false) { break; }
    }
    best
}

pub fn cert_domain_matches(cert_domain: &str, req_domain: &str) -> bool {
    let cd = cert_domain.to_lowercase();
    let rd = req_domain.to_lowercase();
    if cd == rd { return true; }
    if cd.starts_with("*.") {
        let suffix = &cd[1..]; // .example.com
        if rd.ends_with(suffix) {
            let host = &rd[..rd.len() - suffix.len()];
            if !host.contains('.') { return true; }
        }
    }
    false
}

/// Build a rustls ServerConfig from matched TLS rules for the given set of routes.
pub fn build_tls_config(routes: &[WebRoute], tls_rules: &[TlsRule]) -> Option<Arc<rustls::ServerConfig>> {
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
    use std::io::BufReader;

    let mut cert_resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let mut any_added = false;

    for route in routes {
        if !route.enabled || route.domain.is_empty() { continue; }
        let cert_id = &route.matched_cert_id;
        if cert_id.is_empty() { continue; }
        let tls_cert = match tls_rules.iter().find(|c| &c.id == cert_id) {
            Some(c) if !c.cert_pem.is_empty() && !c.key_pem.is_empty() => c,
            _ => continue,
        };

        let cert_chain: Vec<rustls::pki_types::CertificateDer> = {
            let mut reader = BufReader::new(tls_cert.cert_pem.as_bytes());
            match certs(&mut reader) {
                Ok(v) => v.into_iter().map(|c| rustls::pki_types::CertificateDer::from(c.to_vec())).collect(),
                Err(_) => continue,
            }
        };

        let private_key: rustls::pki_types::PrivateKeyDer = {
            let mut reader = BufReader::new(tls_cert.key_pem.as_bytes());
            // Try PKCS8 first, then RSA
            let mut key_bytes = pkcs8_private_keys(&mut reader)
                .ok()
                .and_then(|ks| ks.into_iter().next())
                .map(|k| rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec())));

            if key_bytes.is_none() {
                let mut reader2 = BufReader::new(tls_cert.key_pem.as_bytes());
                key_bytes = rsa_private_keys(&mut reader2)
                    .ok()
                    .and_then(|ks| ks.into_iter().next())
                    .map(|k| rustls::pki_types::PrivateKeyDer::Pkcs1(rustls::pki_types::PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec())));
            }

            match key_bytes {
                Some(k) => k,
                None => continue,
            }
        };

        let certified_key = match rustls::sign::CertifiedKey::new(cert_chain, rustls::crypto::ring::sign::any_supported_type(&private_key).ok()?) {
            ck => Arc::new(ck),
        };

        let domain = route.domain.to_lowercase();
        // Register exact domain
        let _ = cert_resolver.add(&domain, certified_key.clone());
        // Also register with www. prefix if not wildcard
        if !domain.starts_with("*.") {
            let _ = cert_resolver.add(&format!("www.{domain}"), certified_key);
        }
        any_added = true;
    }

    if !any_added { return None; }

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_resolver));
    Some(Arc::new(config))
}

/// Generate HMAC-SHA256 auth session token (same as Go version).
pub fn auth_session_token(route_id: &str, pass_hash: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(pass_hash.as_bytes()).expect("HMAC init");
    mac.update(route_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Build login page HTML (same as Go version).
pub fn build_login_page(next: &str, err_msg: &str, domain: &str) -> String {
    let err_html = if err_msg.is_empty() {
        String::new()
    } else {
        format!("<div class=\"error\">{err_msg}</div>")
    };
    format!(r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
.card{{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 36px;width:100%;max-width:380px}}
.logo{{text-align:center;margin-bottom:28px}}
.logo .icon{{display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:14px;background:#6366f1;margin-bottom:12px}}
.logo .icon svg{{color:#fff}}
.logo h1{{font-size:20px;font-weight:700;color:#1e293b}}
.logo p{{font-size:13px;color:#94a3b8;margin-top:4px}}
label{{display:block;font-size:13px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px}}
input[type=text],input[type=password]{{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:15px;color:#1e293b;background:#f8fafc;outline:none;transition:border .2s}}
input:focus{{border-color:#6366f1;background:#fff}}
.field{{margin-bottom:18px}}
button{{width:100%;padding:12px;border:none;border-radius:10px;background:#6366f1;color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px;transition:background .2s}}
button:hover{{background:#4f46e5}}
button:active{{transform:scale(.98)}}
.error{{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:18px;text-align:center}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="icon">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"/>
        <path d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"/>
      </svg>
    </div>
    <h1>{domain}</h1>
    <p>请登录以继续访问</p>
  </div>
  {err_html}
  <form method="POST" action="/__vane_login__">
    <input type="hidden" name="next" value="{next}">
    <div class="field">
      <label>用户名</label>
      <input type="text" name="username" autocomplete="username" autofocus required>
    </div>
    <div class="field">
      <label>密码</label>
      <input type="password" name="password" autocomplete="current-password" required>
    </div>
    <button type="submit">登录 →</button>
  </form>
</div>
</body>
</html>"#)
}

/// Parse browser name from User-Agent (mirrors Go version).
pub fn parse_browser(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("edg/") || ua_lower.contains("edge/") { return "Edge".to_string(); }
    if ua_lower.contains("chrome") && ua_lower.contains("mobile") { return "Chrome/Android".to_string(); }
    if ua_lower.contains("chrome") { return "Chrome".to_string(); }
    if ua_lower.contains("firefox") { return "Firefox".to_string(); }
    if ua_lower.contains("safari") && ua_lower.contains("mobile") { return "Safari/iOS".to_string(); }
    if ua_lower.contains("safari") { return "Safari".to_string(); }
    if ua_lower.contains("curl") { return "curl".to_string(); }
    if ua_lower.contains("wget") { return "wget".to_string(); }
    if ua.is_empty() { return "—".to_string(); }
    "Other".to_string()
}

/// Match-and-route HTTP request to backend, with auth check.
/// Returns (backend_url, domain, route_id, route_name, Option<(auth_user, auth_pass_hash, route_id_for_cookie, enable_https)>)
pub fn find_route_for_request<'a>(
    rule: &'a WebServiceRule,
    host: &str,
) -> Option<(&'a WebRoute, bool)> {
    let host_bare = host.split(':').next().unwrap_or(host).to_lowercase();

    // Exact domain match (strip www.)
    for route in &rule.routes {
        if !route.enabled { continue; }
        let route_domain = route.domain.trim_start_matches("www.").to_lowercase();
        let req_domain = host_bare.trim_start_matches("www.");
        if route_domain == req_domain || route.domain.is_empty() {
            return Some((route, true));
        }
    }
    // First enabled route as fallback
    rule.routes.iter().find(|r| r.enabled && !r.backend_url.is_empty()).map(|r| (r, false))
}

async fn run_webservice(rule: WebServiceRule, mut stop: oneshot::Receiver<()>, tls_rules: Vec<TlsRule>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::TlsAcceptor;

    let addr: SocketAddr = match format!("0.0.0.0:{}", rule.listen_port).parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[webservice] invalid listen port {}: {e}", rule.listen_port);
            return;
        }
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[webservice] bind {addr} failed: {e}");
            return;
        }
    };

    // Build TLS config if enable_https and we have certs
    let tls_acceptor: Option<TlsAcceptor> = if rule.enable_https {
        build_tls_config(&rule.routes, &tls_rules).map(TlsAcceptor::from)
    } else {
        None
    };

    let rule = Arc::new(rule);
    let tls_rules = Arc::new(tls_rules);
    eprintln!("[webservice] {} listening on {addr} (https={})", rule.id, rule.enable_https);

    loop {
        tokio::select! {
            _ = &mut stop => break,
            c = listener.accept() => {
                if let Ok((stream, peer)) = c {
                    let rule = rule.clone();
                    let tls_rules = tls_rules.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        if let Some(acceptor) = tls_acceptor {
                            // Peek first byte to detect TLS vs plain HTTP
                            // Use TLS acceptor — client sends TLS ClientHello
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    handle_http_connection_tls(tls_stream, peer, rule, tls_rules).await;
                                }
                                Err(e) => {
                                    eprintln!("[webservice] TLS accept error from {peer}: {e}");
                                }
                            }
                        } else {
                            handle_http_connection_plain(stream, peer, rule, tls_rules).await;
                        }
                    });
                }
            }
        }
    }
    eprintln!("[webservice] {} stopped", rule.id);
}

async fn handle_http_connection_plain(
    stream: TcpStream,
    peer: SocketAddr,
    rule: Arc<WebServiceRule>,
    tls_rules: Arc<Vec<TlsRule>>,
) {
    handle_connection_inner(stream, peer, rule, tls_rules, false).await;
}

async fn handle_http_connection_tls(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    rule: Arc<WebServiceRule>,
    tls_rules: Arc<Vec<TlsRule>>,
) {
    handle_connection_inner(stream, peer, rule, tls_rules, true).await;
}

async fn handle_connection_inner<S>(
    mut stream: S,
    peer: SocketAddr,
    rule: Arc<WebServiceRule>,
    _tls_rules: Arc<Vec<TlsRule>>,
    is_https: bool,
) where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() { return; }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 { return; }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers: Vec<(String, String)> = vec![];
    let mut host_header = String::new();
    let mut content_length: usize = 0;
    let mut cookie_header = String::new();

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() { break; }
        let line = line.trim_end();
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "host" { host_header = val.clone(); }
            if key == "content-length" { content_length = val.parse().unwrap_or(0); }
            if key == "cookie" { cookie_header = val.clone(); }
            headers.push((key, val));
        }
    }

    let body = if content_length > 0 {
        let mut body = vec![0u8; content_length.min(16 * 1024 * 1024)];
        let _ = reader.read_exact(&mut body).await;
        body
    } else {
        vec![]
    };

    let matched_route = match find_route_for_request(&rule, &host_header) {
        Some((r, _)) => r.clone(),
        None => {
            let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            let _ = write_half.write_all(resp.as_bytes()).await;
            return;
        }
    };

    // Auth check (cookie-based, like Go version)
    if matched_route.auth_enabled && !matched_route.auth_pass_hash.is_empty() {
        let cookie_name = format!("vane_auth_{}", &matched_route.id[..8.min(matched_route.id.len())]);
        let session_token = auth_session_token(&matched_route.id, &matched_route.auth_pass_hash);

        let cookie_ok = cookie_header.split(';').any(|c| {
            let c = c.trim();
            if let Some((k, v)) = c.split_once('=') {
                k.trim() == cookie_name && v.trim() == session_token
            } else {
                false
            }
        });

        if !cookie_ok {
            // Handle login form POST
            if method == "POST" && path == "/__vane_login__" {
                let form_str = String::from_utf8_lossy(&body);
                let mut user = String::new();
                let mut pass = String::new();
                let mut next = String::new();
                for part in form_str.split('&') {
                    if let Some((k, v)) = part.split_once('=') {
                        let v = urlencoding::decode(v).unwrap_or_default().to_string();
                        match k {
                            "username" => user = v,
                            "password" => pass = v,
                            "next" => next = v,
                            _ => {}
                        }
                    }
                }
                if next.is_empty() { next = "/".to_string(); }

                let auth_ok = user == matched_route.auth_user
                    && bcrypt::verify(&pass, &matched_route.auth_pass_hash).unwrap_or(false);

                if auth_ok {
                    let secure_flag = if is_https { "; Secure" } else { "" };
                    let set_cookie = format!(
                        "{cookie_name}={session_token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax{secure_flag}"
                    );
                    let resp = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {next}\r\nSet-Cookie: {set_cookie}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = write_half.write_all(resp.as_bytes()).await;
                    return;
                } else {
                    let page = build_login_page(&path, "用户名或密码错误", &matched_route.domain);
                    let resp = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{page}", page.len());
                    let _ = write_half.write_all(resp.as_bytes()).await;
                    return;
                }
            }
            // Show login page
            let page = build_login_page(&path, "", &matched_route.domain);
            let resp = format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{page}", page.len());
            let _ = write_half.write_all(resp.as_bytes()).await;
            return;
        }
    }

    let backend = matched_route.backend_url.trim_end_matches('/');
    if backend.is_empty() {
        let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        let _ = write_half.write_all(resp.as_bytes()).await;
        return;
    }

    let upstream_url = format!("{backend}{path}");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_default();

    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );
    for (k, v) in &headers {
        match k.as_str() {
            "host" | "connection" | "transfer-encoding" => {}
            _ => { req = req.header(k.as_str(), v.as_str()); }
        }
    }
    req = req
        .header("X-Forwarded-For", peer.ip().to_string())
        .header("X-Real-IP", peer.ip().to_string())
        .header("Host", &host_header)
        .body(body);

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let mut response = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
            for (k, v) in resp.headers() {
                if let Ok(val) = v.to_str() {
                    response.push_str(&format!("{}: {val}\r\n", k.as_str()));
                }
            }
            response.push_str("\r\n");
            let body_bytes = resp.bytes().await.unwrap_or_default();
            let _ = write_half.write_all(response.as_bytes()).await;
            let _ = write_half.write_all(&body_bytes).await;
        }
        Err(e) => {
            let msg = format!("upstream error: {e}");
            let resp = format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{msg}", msg.len());
            let _ = write_half.write_all(resp.as_bytes()).await;
        }
    }
}

// ─── TLS auto-renew watcher ───────────────────────────────────────────────────

async fn run_tls_autorenew(
    rule: TlsRule,
    mut stop: oneshot::Receiver<()>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
) {
    // First check after 1 hour, then every 12 hours
    tokio::time::sleep(Duration::from_secs(3600)).await;
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(12 * 3600)) => {}
        }
        if !rule.auto_renew { continue; }
        let days = rule.days_until_expiry();
        if days >= 0 && days <= 30 {
            eprintln!("[tls] cert {} expiring in {days} days, auto-renewing", rule.id);
            match crate::acme::issue_cert(&rule).await {
                Ok((cert_pem, key_pem, issued_at, expires_at)) => {
                    let mut d = data.write().await;
                    if let Some(x) = d.tls.iter_mut().find(|x| x.id == rule.id) {
                        x.cert_pem = cert_pem;
                        x.key_pem = key_pem;
                        x.issued_at = issued_at;
                        x.expires_at = expires_at;
                        x.status = "active".to_string();
                        x.error_msg.clear();
                    }
                }
                Err(e) => {
                    eprintln!("[tls] auto-renew {} failed: {e}", rule.id);
                    let mut d = data.write().await;
                    if let Some(x) = d.tls.iter_mut().find(|x| x.id == rule.id) {
                        x.status = "error".to_string();
                        x.error_msg = e.to_string();
                    }
                }
            }
        }
    }
}

/// Update matched_cert_id and cert_status for all routes in all services.
pub async fn rematch_all_routes(data: &Arc<RwLock<crate::models::RuntimeData>>) {
    let mut d = data.write().await;
    let tls_rules = d.tls.clone();
    for svc in &mut d.webservice {
        for route in &mut svc.routes {
            match find_tls_cert(&tls_rules, &route.domain) {
                Some(cert) => {
                    route.matched_cert_id = cert.id.clone();
                    route.cert_status = if cert.status == "active" { "ok".to_string() } else { "cert_inactive".to_string() };
                }
                None => {
                    route.matched_cert_id.clear();
                    route.cert_status = "no_cert".to_string();
                }
            }
        }
    }
}

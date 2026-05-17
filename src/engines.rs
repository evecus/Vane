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

use crate::models::{AdminConfig, Config, DdnsRule, IpRecord, PortForwardRule, TlsRule, WebServiceRule};
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

    pub async fn apply_webservice(&self, rules: &[WebServiceRule]) {
        reconcile_spawn(
            &self.webservice,
            rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
            |r, rx| { tokio::spawn(run_webservice(r, rx)); },
        )
        .await;
    }

    pub async fn apply_tls(
        &self,
        rules: &[TlsRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
        cfg: Config,
    ) {
        reconcile_spawn(
            &self.tls,
            rules.iter().filter(|r| r.enabled && r.auto_renew).map(|r| (r.id.clone(), r.clone())).collect(),
            move |r, rx| {
                let data = data.clone();
                let cfg = cfg.clone();
                tokio::spawn(run_tls_autorenew(r, rx, data, cfg));
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
    let listen: SocketAddr = match rule.listen.parse() {
        Ok(v) => v,
        Err(_) => {
            // Try bare port number
            match format!("0.0.0.0:{}", rule.listen).parse() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[portforward] invalid listen addr {:?}: {e}", rule.listen);
                    return;
                }
            }
        }
    };
    let target: SocketAddr = match rule.target.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] invalid target addr {:?}: {e}", rule.target);
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
    // Try multiple sources for resilience
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
                    if !ip.is_empty() {
                        return Ok(ip);
                    }
                }
            }
            Err(e) => last_err = e.into(),
        }
    }
    Err(last_err)
}

fn get_interface_ip(iface: &str, ip_version: &str, index: i32) -> Option<String> {
    let ips = super::handlers::collect_iface_ips(iface, ip_version);
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
        // List existing records
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
                .json(&serde_json::json!({
                    "type": record_type,
                    "name": fqdn,
                    "content": ip,
                    "proxied": false
                }))
                .send()
                .await?;
        } else {
            client
                .post(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
                ))
                .bearer_auth(token)
                .timeout(Duration::from_secs(15))
                .json(&serde_json::json!({
                    "type": record_type,
                    "name": fqdn,
                    "content": ip,
                    "proxied": false
                }))
                .send()
                .await?;
        }
    }
    Ok(())
}

async fn sync_alidns(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    use std::collections::BTreeMap;

    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    if key_id.is_empty() || key_secret.is_empty() {
        return Err(anyhow::anyhow!("AliDNS requires access_key_id and access_key_secret"));
    }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (rr, domain) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("@", fqdn.as_str())
        };

        // First: DescribeDomainRecords to find existing record
        let describe_params = build_aliyun_params(
            key_id,
            "DescribeDomainRecords",
            &[
                ("DomainName", domain),
                ("RRKeyWord", rr),
                ("TypeKeyWord", record_type),
            ],
        );

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
            // UpdateDomainRecord
            let update_params = build_aliyun_params(
                key_id,
                "UpdateDomainRecord",
                &[
                    ("RecordId", rid.as_str()),
                    ("RR", rr),
                    ("Type", record_type),
                    ("Value", ip),
                ],
            );
            client
                .get("https://alidns.aliyuncs.com/")
                .query(&sign_aliyun_params(&update_params, key_secret))
                .timeout(Duration::from_secs(15))
                .send()
                .await?;
        } else {
            // AddDomainRecord
            let add_params = build_aliyun_params(
                key_id,
                "AddDomainRecord",
                &[
                    ("DomainName", domain),
                    ("RR", rr),
                    ("Type", record_type),
                    ("Value", ip),
                ],
            );
            client
                .get("https://alidns.aliyuncs.com/")
                .query(&sign_aliyun_params(&add_params, key_secret))
                .timeout(Duration::from_secs(15))
                .send()
                .await?;
        }
    }
    Ok(())
}

fn build_aliyun_params<'a>(
    key_id: &'a str,
    action: &'a str,
    extra: &[(&'a str, &'a str)],
) -> Vec<(String, String)> {
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
    for (k, v) in extra {
        params.push((k.to_string(), v.to_string()));
    }
    params
}

fn sign_aliyun_params(params: &[(String, String)], secret: &str) -> Vec<(String, String)> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let query_str: String = sorted
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                urlencoding::encode(k),
                urlencoding::encode(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&");

    let string_to_sign = format!(
        "GET&{}&{}",
        urlencoding::encode("/"),
        urlencoding::encode(&query_str)
    );

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
    if token.is_empty() {
        return Err(anyhow::anyhow!("DNSPod requires api_token"));
    }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

    for fqdn in &domains {
        // Split into subdomain and root
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (sub, domain) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("@", fqdn.as_str())
        };

        // Get record list
        let list: serde_json::Value = client
            .post("https://dnsapi.cn/Record.List")
            .form(&[
                ("login_token", token.as_str()),
                ("format", "json"),
                ("domain", domain),
                ("sub_domain", sub),
            ])
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .json()
            .await?;

        let record_id = list["records"]
            .as_array()
            .and_then(|a| {
                a.iter().find(|r| {
                    r["type"].as_str().map(|t| t == record_type).unwrap_or(false)
                })
            })
            .and_then(|r| r["id"].as_str())
            .map(|s| s.to_string());

        if let Some(rid) = record_id {
            client
                .post("https://dnsapi.cn/Record.Modify")
                .form(&[
                    ("login_token", token.as_str()),
                    ("format", "json"),
                    ("domain", domain),
                    ("record_id", rid.as_str()),
                    ("sub_domain", sub),
                    ("record_type", record_type),
                    ("value", ip),
                    ("record_line", "默认"),
                ])
                .timeout(Duration::from_secs(15))
                .send()
                .await?;
        } else {
            client
                .post("https://dnsapi.cn/Record.Create")
                .form(&[
                    ("login_token", token.as_str()),
                    ("format", "json"),
                    ("domain", domain),
                    ("sub_domain", sub),
                    ("record_type", record_type),
                    ("value", ip),
                    ("record_line", "默认"),
                ])
                .timeout(Duration::from_secs(15))
                .send()
                .await?;
        }
    }
    Ok(())
}

async fn sync_tencent(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    // Tencent Cloud DNS uses the same DNSPod API (token auth)
    // The DNSPod token for Tencent is "secretId,secretKey"
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    if secret_id.is_empty() || secret_key.is_empty() {
        return Err(anyhow::anyhow!("Tencent DNS requires secret_id and secret_key"));
    }

    // Compose DNSPod-compatible token: "id,key"
    let token = format!("{secret_id},{secret_key}");
    let mut proxy_rule = rule.clone();
    proxy_rule.provider_conf.api_token = token;
    sync_dnspod(client, &proxy_rule, ip).await
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

// ─── Web Service ──────────────────────────────────────────────────────────────

async fn run_webservice(rule: WebServiceRule, mut stop: oneshot::Receiver<()>) {
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

    let rule = Arc::new(rule);
    eprintln!("[webservice] {} listening on {addr}", rule.id);

    loop {
        tokio::select! {
            _ = &mut stop => break,
            c = listener.accept() => {
                if let Ok((stream, peer)) = c {
                    let rule = rule.clone();
                    tokio::spawn(handle_http_connection(stream, peer, rule));
                }
            }
        }
    }
    eprintln!("[webservice] {} stopped", rule.id);
}

async fn handle_http_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    rule: Arc<WebServiceRule>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);

    // Read request line
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Read headers
    let mut headers: Vec<(String, String)> = vec![];
    let mut host_header = String::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "host" {
                host_header = val.clone();
            }
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    // Read body if present
    let body = if content_length > 0 {
        let mut body = vec![0u8; content_length.min(16 * 1024 * 1024)];
        let _ = reader.read_exact(&mut body).await;
        body
    } else {
        vec![]
    };

    // Find matching route
    let (backend_url, route_auth) = find_backend_with_auth(&rule, &host_header, &path);
    if backend_url.is_empty() {
        let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        let _ = write_half.write_all(resp.as_bytes()).await;
        return;
    }

    // Basic auth check
    if let Some((auth_user, auth_hash)) = route_auth {
        let auth_ok = headers.iter().any(|(k, v)| {
            if k != "authorization" { return false; }
            // "Basic base64(user:pass)"
            if let Some(b64) = v.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                    if let Ok(s) = std::str::from_utf8(&decoded) {
                        if let Some((u, p)) = s.split_once(':') {
                            return u == auth_user && crate::auth::bcrypt_verify(p, &auth_hash);
                        }
                    }
                }
            }
            false
        });
        if !auth_ok {
            let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\nContent-Length: 0\r\n\r\n";
            let _ = write_half.write_all(resp.as_bytes()).await;
            return;
        }
    }

    let upstream_base = backend_url.trim_end_matches('/');
    let upstream_url = format!("{upstream_base}{path}");

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
            _ => {
                req = req.header(k.as_str(), v.as_str());
            }
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
            let mut response = format!(
                "HTTP/1.1 {} {}\r\n",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            );
            for (k, v) in resp.headers() {
                if let Ok(val) = v.to_str() {
                    response.push_str(&format!("{}: {val}\r\n", k.as_str()));
                }
            }
            response.push_str("\r\n");
            let body = resp.bytes().await.unwrap_or_default();
            let _ = write_half.write_all(response.as_bytes()).await;
            let _ = write_half.write_all(&body).await;
        }
        Err(e) => {
            let msg = format!("upstream error: {e}");
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{msg}",
                msg.len()
            );
            let _ = write_half.write_all(resp.as_bytes()).await;
        }
    }
}

/// Returns (backend_url, Option<(auth_user, auth_pass_hash)>)
fn find_backend_with_auth(
    rule: &WebServiceRule,
    host: &str,
    path: &str,
) -> (String, Option<(String, String)>) {
    let host_bare = host.split(':').next().unwrap_or(host);

    // Exact domain match
    for route in &rule.routes {
        if !route.enabled { continue; }
        if route.domain == host_bare || route.domain == host || route.domain.is_empty() {
            let auth = if route.auth_enabled && !route.auth_user.is_empty() && !route.auth_pass_hash.is_empty() {
                Some((route.auth_user.clone(), route.auth_pass_hash.clone()))
            } else {
                None
            };
            return (route.backend_url.clone(), auth);
        }
    }

    // Path prefix fallback
    for route in &rule.routes {
        if !route.enabled { continue; }
        if !route.backend_url.is_empty() && (path.starts_with(route.domain.as_str()) || route.domain.is_empty()) {
            let auth = if route.auth_enabled && !route.auth_user.is_empty() && !route.auth_pass_hash.is_empty() {
                Some((route.auth_user.clone(), route.auth_pass_hash.clone()))
            } else {
                None
            };
            return (route.backend_url.clone(), auth);
        }
    }

    // First enabled route
    if let Some(route) = rule.routes.iter().find(|r| r.enabled && !r.backend_url.is_empty()) {
        let auth = if route.auth_enabled && !route.auth_user.is_empty() && !route.auth_pass_hash.is_empty() {
            Some((route.auth_user.clone(), route.auth_pass_hash.clone()))
        } else {
            None
        };
        return (route.backend_url.clone(), auth);
    }

    (String::new(), None)
}

// ─── TLS auto-renew watcher ───────────────────────────────────────────────────

async fn run_tls_autorenew(
    rule: TlsRule,
    mut stop: oneshot::Receiver<()>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    _cfg: Config,
) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(12 * 3600)) => {
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
    }
}

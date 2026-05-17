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

use crate::models::{DdnsRule, PortForwardRule, TlsRule, WebServiceRule};

// ─── RuntimeEngines ──────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct RuntimeEngines {
    pub portforward: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub ddns: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub webservice: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub tls: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
}

impl RuntimeEngines {
    pub async fn apply_portforwards(&self, rules: &[PortForwardRule]) {
        reconcile_spawn(
            &self.portforward,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            |r, rx| {
                tokio::spawn(run_forwarder(r, rx));
            },
        )
        .await;
    }

    pub async fn apply_ddns(&self, rules: &[DdnsRule]) {
        reconcile_spawn(
            &self.ddns,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            |r, rx| {
                tokio::spawn(run_ddns(r, rx));
            },
        )
        .await;
    }

    pub async fn apply_webservice(&self, rules: &[WebServiceRule]) {
        reconcile_spawn(
            &self.webservice,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            |r, rx| {
                tokio::spawn(run_webservice(r, rx));
            },
        )
        .await;
    }

    pub async fn apply_tls(&self, rules: &[TlsRule]) {
        reconcile_spawn(
            &self.tls,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            |r, rx| {
                tokio::spawn(run_tls_autorenew(r, rx));
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
        let existing: Vec<String> = m.keys().cloned().collect();
        for id in existing {
            if !ids.contains(&id) {
                if let Some(tx) = m.remove(&id) {
                    let _ = tx.send(());
                }
            }
        }
    }
    for (id, r) in enabled {
        let mut m = map.write().await;
        if m.contains_key(&id) {
            continue;
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
        Err(e) => {
            eprintln!("[portforward] invalid listen addr {:?}: {e}", rule.listen);
            return;
        }
    };
    let target: SocketAddr = match rule.target.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] invalid target addr {:?}: {e}", rule.target);
            return;
        }
    };

    if rule.protocol.eq_ignore_ascii_case("udp") {
        run_udp_forwarder(listen, target, stop).await;
        return;
    }

    if !rule.protocol.eq_ignore_ascii_case("tcp") {
        eprintln!("[portforward] unsupported protocol {:?}", rule.protocol);
        return;
    }

    let listener = match TcpListener::bind(listen).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] bind {listen} failed: {e}");
            return;
        }
    };
    eprintln!("[portforward] {} listening on {listen} -> {target}", rule.id);
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

/// UDP forwarder — per-client NAT table so multiple clients work correctly.
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

    // client_addr -> outbound socket
    let nat: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut stop => break,
            r = inbound.recv_from(&mut buf) => {
                let (n, client) = match r { Ok(x) => x, Err(_) => continue };
                let data = buf[..n].to_vec();

                // Get or create outbound socket for this client
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

                        // Spawn reply listener for this client's socket
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
                                // Evict if client vanished
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

async fn run_ddns(rule: DdnsRule, mut stop: oneshot::Receiver<()>) {
    let client = Client::new();
    // Run immediately on start
    let _ = sync_ddns_provider(&client, &rule).await;
    let interval_secs = if rule.interval > 0 { rule.interval as u64 } else { 300 };
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(interval_secs)) => {
                let _ = sync_ddns_provider(&client, &rule).await;
            }
        }
    }
}

pub async fn sync_ddns_provider(client: &Client, rule: &DdnsRule) -> anyhow::Result<String> {
    let ip = get_public_ip(client, &rule.ip_version).await?;

    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => sync_cloudflare(client, rule, &ip).await?,
        "alidns" | "aliyun" => sync_alidns(client, rule, &ip).await?,
        "dnspod" => sync_dnspod(client, rule, &ip).await?,
        "tencent" | "tencentcloud" => sync_tencent(client, rule, &ip).await?,
        _ => eprintln!("[ddns] unknown provider {:?}", rule.provider),
    }
    Ok(ip)
}

async fn get_public_ip(client: &Client, ip_version: &str) -> anyhow::Result<String> {
    let url = if ip_version == "ipv6" {
        "https://api6.ipify.org"
    } else {
        "https://api.ipify.org"
    };
    let ip = client.get(url).send().await?.text().await?;
    Ok(ip.trim().to_string())
}

async fn sync_cloudflare(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;
    if token.is_empty() || zone.is_empty() {
        return Ok(());
    }

    let domains = effective_domains(rule);
    for fqdn in domains {
        let record_type = if rule.ip_version == "ipv6" { "AAAA" } else { "A" };

        // List existing records
        let recs: serde_json::Value = client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type={record_type}&name={fqdn}"
            ))
            .bearer_auth(token)
            .send()
            .await?
            .json()
            .await?;

        if let Some(rid) = recs["result"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|x| x["id"].as_str())
        {
            // Update
            client
                .put(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rid}"
                ))
                .bearer_auth(token)
                .json(&serde_json::json!({
                    "type": record_type,
                    "name": fqdn,
                    "content": ip,
                    "proxied": false
                }))
                .send()
                .await?;
        } else {
            // Create
            client
                .post(format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
                ))
                .bearer_auth(token)
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
    // Aliyun DNS requires HMAC-SHA1 signed requests. We use the open API approach
    // with AccessKeyId + AccessKeySecret via the official parameter signing scheme.
    // For brevity we call the same endpoint structure but note that production use
    // requires proper signature implementation (alibaba-cloud-sdk-go equivalent).
    let _id = &rule.provider_conf.access_key_id;
    let _secret = &rule.provider_conf.access_key_secret;
    let domains = effective_domains(rule);
    for fqdn in &domains {
        eprintln!("[ddns/alidns] would update {fqdn} -> {ip} (requires HMAC-SHA1 signing, implement SDK)");
    }
    Ok(())
}

async fn sync_dnspod(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    if token.is_empty() {
        return Ok(());
    }
    let domains = effective_domains(rule);
    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let sub = if parts.len() == 2 { parts[0] } else { "@" };
        let domain = if parts.len() == 2 { parts[1] } else { fqdn.as_str() };

        client
            .post("https://dnsapi.cn/Record.Ddns")
            .form(&[
                ("login_token", token.as_str()),
                ("format", "json"),
                ("domain", domain),
                ("sub_domain", sub),
                ("record_type", if rule.ip_version == "ipv6" { "AAAA" } else { "A" }),
                ("value", ip),
            ])
            .send()
            .await?;
    }
    Ok(())
}

async fn sync_tencent(client: &Client, rule: &DdnsRule, ip: &str) -> anyhow::Result<()> {
    // Tencent Cloud DNS (DNSPod API v3) requires TC3-HMAC-SHA256 signature.
    let _secret_id = &rule.provider_conf.secret_id;
    let _secret_key = &rule.provider_conf.secret_key;
    let domains = effective_domains(rule);
    for fqdn in &domains {
        eprintln!("[ddns/tencent] would update {fqdn} -> {ip} (requires TC3-HMAC-SHA256, implement SDK)");
    }
    Ok(())
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

/// Web service engine: HTTP reverse proxy via hyper.
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
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(&mut stream);
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
            headers.push((key, val));
        }
    }

    // Find best matching route by domain then path
    let backend_url = find_backend(&rule, &host_header, &path);
    if backend_url.is_empty() {
        let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return;
    }

    // Build upstream request URL
    let upstream_base = backend_url.trim_end_matches('/');
    let upstream_url = format!("{upstream_base}{path}");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let mut req = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );
    // Forward select headers
    for (k, v) in &headers {
        match k.as_str() {
            "host" | "connection" | "transfer-encoding" => {}
            _ => { req = req.header(k.as_str(), v.as_str()); }
        }
    }
    req = req.header("X-Forwarded-For", peer.ip().to_string());
    req = req.header("X-Real-IP", peer.ip().to_string());
    req = req.header("Host", host_header.clone());

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
            let body = resp.bytes().await.unwrap_or_default();
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
        Err(e) => {
            let msg = format!("upstream error: {e}");
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\n\r\n{msg}",
                msg.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    }
}

fn find_backend(rule: &WebServiceRule, host: &str, path: &str) -> String {
    // Try to match by domain first
    let host_bare = host.split(':').next().unwrap_or(host);
    for route in &rule.routes {
        if !route.enabled {
            continue;
        }
        if route.domain == host_bare || route.domain == host {
            return route.backend_url.clone();
        }
    }
    // Fall back to path prefix matching
    for route in &rule.routes {
        if !route.enabled {
            continue;
        }
        if !route.backend_url.is_empty() && path.starts_with(route.domain.as_str()) {
            return route.backend_url.clone();
        }
    }
    // First enabled route as fallback
    rule.routes
        .iter()
        .find(|r| r.enabled && !r.backend_url.is_empty())
        .map(|r| r.backend_url.clone())
        .unwrap_or_default()
}

// ─── TLS auto-renew watcher ───────────────────────────────────────────────────

async fn run_tls_autorenew(rule: TlsRule, mut stop: oneshot::Receiver<()>) {
    // Check every 12 hours
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(12 * 3600)) => {
                if rule.auto_renew && rule.source == "acme" && rule.days_until_expiry() <= 30 {
                    eprintln!("[tls] cert {} expiring in {} days, trigger renew via API", rule.id, rule.days_until_expiry());
                    // Actual renewal is triggered via the /api/tls/:id/renew endpoint or
                    // the background task in main. The engine just watches and logs.
                }
            }
        }
    }
}

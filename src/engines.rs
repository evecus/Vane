//! Runtime engine management: port-forward, DDNS, web-service, TLS auto-renew.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use reqwest::Client;
use tokio::{
    io,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, RwLock},
    time,
};

use crate::db::Db;
use crate::models::{
    Config, DdnsRule, IpFilterRule, IpRecord, PortForwardRule, TlsRule, WebRoute, WebServiceRule,
};
use crate::state::now_rfc3339;

// hyper reverse-proxy imports

// ─── Port-forward stats ───────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatSnapshot {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub conns: i64,
    pub time: String,
}

/// Global per-rule stats: id -> (bytes_in, bytes_out, active_conns)
pub type StatsStore = Arc<RwLock<HashMap<String, Arc<PfStats>>>>;

pub struct PfStats {
    pub bytes_in: std::sync::atomic::AtomicI64,
    pub bytes_out: std::sync::atomic::AtomicI64,
    pub conns: std::sync::atomic::AtomicI64,
}

impl PfStats {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_in: std::sync::atomic::AtomicI64::new(0),
            bytes_out: std::sync::atomic::AtomicI64::new(0),
            conns: std::sync::atomic::AtomicI64::new(0),
        })
    }
    fn snapshot(&self) -> StatSnapshot {
        StatSnapshot {
            bytes_in: self.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            bytes_out: self.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            conns: self.conns.load(std::sync::atomic::Ordering::Relaxed),
            time: crate::state::now_rfc3339(),
        }
    }
}

/// Global history: id -> ring-buffer of last 360 snapshots (5s interval = 30 min)
pub type HistoryStore = Arc<RwLock<HashMap<String, Vec<StatSnapshot>>>>;

// ─── RuntimeEngines ──────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct RuntimeEngines {
    pub portforward: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub ddns: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub webservice: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub tls: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    pub pf_stats: StatsStore,
    pub pf_history: HistoryStore,
}

impl RuntimeEngines {
    pub async fn apply_portforwards(
        &self,
        rules: &[PortForwardRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
    ) {
        let stats = self.pf_stats.clone();
        let history = self.pf_history.clone();

        // Start the 5-second stats collector once
        {
            static COLLECTOR_STARTED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !COLLECTOR_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let stats2 = stats.clone();
                let history2 = history.clone();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(5));
                    loop {
                        ticker.tick().await;
                        let snap_map: Vec<(String, StatSnapshot)> = {
                            let s = stats2.read().await;
                            s.iter()
                                .map(|(id, st)| (id.clone(), st.snapshot()))
                                .collect()
                        };
                        let mut h = history2.write().await;
                        for (id, snap) in snap_map {
                            let entry = h.entry(id).or_default();
                            entry.push(snap);
                            if entry.len() > 360 {
                                entry.remove(0);
                            }
                        }
                    }
                });
            }
        }

        let active_ids: std::collections::HashSet<String> = rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.id.clone())
            .collect();
        stats.write().await.retain(|id, _| active_ids.contains(id));

        reconcile_spawn(
            &self.portforward,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            move |r, rx| {
                let stats3 = stats.clone();
                let data3 = data.clone();
                tokio::spawn(async move {
                    let st = {
                        let mut s = stats3.write().await;
                        s.entry(r.id.clone()).or_insert_with(PfStats::new).clone()
                    };
                    run_forwarder_with_stats(r, rx, st, data3).await;
                });
            },
        )
        .await;
    }

    pub async fn get_pf_history(&self, id: &str) -> Vec<StatSnapshot> {
        self.pf_history
            .read()
            .await
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// Stop a single DDNS worker by id (used by refresh-now to prevent race).
    pub async fn stop_ddns(&self, id: &str) {
        if let Some(tx) = self.ddns.write().await.remove(id) {
            let _ = tx.send(());
        }
    }

    pub async fn apply_ddns(
        &self,
        rules: &[DdnsRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
        db: Db,
    ) {
        reconcile_spawn(
            &self.ddns,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            move |r, rx| {
                let data = data.clone();
                let db = db.clone();
                tokio::spawn(run_ddns(r, rx, data, db));
            },
        )
        .await;
    }

    pub async fn apply_webservice(
        &self,
        rules: &[WebServiceRule],
        tls_rules: &[TlsRule],
        ipfilter: &[crate::models::IpFilterRule],
        db: Db,
        data: Arc<RwLock<crate::models::RuntimeData>>,
    ) {
        self.apply_webservice_inner(rules, tls_rules, ipfilter, db, data, false).await;
    }

    pub async fn apply_webservice_force(
        &self,
        rules: &[WebServiceRule],
        tls_rules: &[TlsRule],
        ipfilter: &[crate::models::IpFilterRule],
        db: Db,
        data: Arc<RwLock<crate::models::RuntimeData>>,
    ) {
        self.apply_webservice_inner(rules, tls_rules, ipfilter, db, data, true).await;
    }

    async fn apply_webservice_inner(
        &self,
        rules: &[WebServiceRule],
        tls_rules: &[TlsRule],
        ipfilter: &[crate::models::IpFilterRule],
        db: Db,
        data: Arc<RwLock<crate::models::RuntimeData>>,
        force_restart: bool,
    ) {
        let tls_rules = tls_rules.to_vec();
        let ipfilter = ipfilter.to_vec();
        let spawn_fn = move |r: WebServiceRule, rx| {
            let tls = tls_rules.clone();
            let ipf = ipfilter.clone();
            let db2 = db.clone();
            let data2 = data.clone();
            tokio::spawn(run_webservice(
                r.id.clone(),
                r.listen_port,
                r.enable_https,
                rx,
                tls,
                ipf,
                db2,
                data2,
            ));
        };
        if force_restart {
            reconcile_spawn_force(
                &self.webservice,
                rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
                spawn_fn,
            ).await;
        } else {
            reconcile_spawn(
                &self.webservice,
                rules.iter().filter(|r| r.enabled).map(|r| (r.id.clone(), r.clone())).collect(),
                spawn_fn,
            ).await;
        }
    }

    pub async fn apply_tls(
        &self,
        rules: &[TlsRule],
        data: Arc<RwLock<crate::models::RuntimeData>>,
        _cfg: Config,
        db: Db,
    ) {
        reconcile_spawn(
            &self.tls,
            rules
                .iter()
                .filter(|r| r.enabled && r.auto_renew)
                .map(|r| (r.id.clone(), r.clone()))
                .collect(),
            move |r, rx| {
                let data = data.clone();
                let db = db.clone();
                tokio::spawn(run_tls_autorenew(r, rx, data, db));
            },
        )
        .await;
    }
}

async fn reconcile_spawn<T: Clone + Send + 'static, F>(
    map: &Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    enabled: Vec<(String, T)>,
    mut spawn: F,
) where
    F: FnMut(T, oneshot::Receiver<()>),
{
    reconcile_spawn_inner(map, enabled, false, spawn).await;
}

async fn reconcile_spawn_force<T: Clone + Send + 'static, F>(
    map: &Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    enabled: Vec<(String, T)>,
    mut spawn: F,
) where
    F: FnMut(T, oneshot::Receiver<()>),
{
    reconcile_spawn_inner(map, enabled, true, spawn).await;
}

async fn reconcile_spawn_inner<T: Clone + Send + 'static, F>(
    map: &Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    enabled: Vec<(String, T)>,
    force_restart: bool,
    mut spawn: F,
) where
    F: FnMut(T, oneshot::Receiver<()>),
{
    let ids: std::collections::HashSet<_> = enabled.iter().map(|(id, _)| id.clone()).collect();
    {
        let mut m = map.write().await;
        // Stop removed entries
        let to_stop: Vec<String> = m.keys().filter(|k| !ids.contains(*k)).cloned().collect();
        for id in to_stop {
            if let Some(tx) = m.remove(&id) {
                let _ = tx.send(());
            }
        }
        // If force_restart, also stop entries that are being re-added
        if force_restart {
            for (id, _) in &enabled {
                if let Some(tx) = m.remove(id) {
                    let _ = tx.send(());
                }
            }
        }
    }
    // Small delay when force-restarting to let OS free the port
    if force_restart && !enabled.is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    for (id, r) in enabled {
        let mut m = map.write().await;
        if m.contains_key(&id) {
            continue; // already running (not force)
        }
        let (tx, rx) = oneshot::channel();
        m.insert(id, tx);
        spawn(r, rx);
    }
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

async fn run_forwarder_with_stats(
    rule: PortForwardRule,
    stop: oneshot::Receiver<()>,
    stats: Arc<PfStats>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
) {
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

    // "both" = start TCP + UDP concurrently
    let rule_id = rule.id.clone();
    if proto == "both" {
        let (stop_tx1, stop_rx1) = oneshot::channel::<()>();
        let (stop_tx2, stop_rx2) = oneshot::channel::<()>();
        let stats1 = stats.clone();
        let data1 = data.clone();
        let data2 = data.clone();
        let rid1 = rule_id.clone();
        let rid2 = rule_id.clone();
        let t1 = tokio::spawn(run_tcp_forwarder(
            listen, target, stop_rx1, stats1, data1, rid1,
        ));
        let t2 = tokio::spawn(run_udp_forwarder(listen, target, stop_rx2, data2, rid2));
        let _ = stop.await;
        let _ = stop_tx1.send(());
        let _ = stop_tx2.send(());
        let _ = tokio::join!(t1, t2);
        return;
    }

    if proto == "udp" {
        run_udp_forwarder(listen, target, stop, data, rule_id).await;
        return;
    }

    // Default to TCP
    run_tcp_forwarder(listen, target, stop, stats, data, rule_id).await;
    eprintln!("[portforward] {} stopped", rule.id);
}

async fn run_tcp_forwarder(
    listen: SocketAddr,
    target: SocketAddr,
    mut stop: oneshot::Receiver<()>,
    stats: Arc<PfStats>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    rule_id: String,
) {
    let listener = match TcpListener::bind(listen).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[portforward] TCP bind {listen} failed: {e}");
            return;
        }
    };
    eprintln!("[portforward] TCP {listen} -> {target}");
    loop {
        tokio::select! {
            _ = &mut stop => break,
            c = listener.accept() => {
                if let Ok((inbound, peer)) = c {
                    let client_ip = peer.ip().to_string();
                    // Live IP filter check
                    let ipfilter = data.read().await.ipfilter.clone();
                    if !ip_allowed(&ipfilter, "portforward", &rule_id, &client_ip) {
                        eprintln!("[portforward] TCP blocked {client_ip} → {listen}");
                        drop(inbound);
                        continue;
                    }
                    let st = stats.clone();
                    st.conns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::spawn(async move {
                        proxy_tcp_stats(inbound, target, st).await;
                    });
                }
            }
        }
    }
}

async fn proxy_tcp_stats(inbound: TcpStream, target: SocketAddr, stats: Arc<PfStats>) {
    if let Ok(outbound) = TcpStream::connect(target).await {
        let (mut ri, mut wi) = inbound.into_split();
        let (mut ro, mut wo) = outbound.into_split();
        let st1 = stats.clone();
        let st2 = stats.clone();
        let t1 = tokio::spawn(async move {
            let n = tokio::io::copy(&mut ri, &mut wo).await.unwrap_or(0);
            st1.bytes_in
                .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
        });
        let t2 = tokio::spawn(async move {
            let n = tokio::io::copy(&mut ro, &mut wi).await.unwrap_or(0);
            st2.bytes_out
                .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
        });
        let _ = tokio::join!(t1, t2);
    }
    stats
        .conns
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}

// Keep old proxy_tcp for backward compat
#[allow(dead_code)]
async fn proxy_tcp(mut inbound: TcpStream, target: SocketAddr) {
    if let Ok(mut outbound) = TcpStream::connect(target).await {
        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
    }
}

async fn run_udp_forwarder(
    listen: SocketAddr,
    target: SocketAddr,
    mut stop: oneshot::Receiver<()>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    rule_id: String,
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
                // Live IP filter check
                {
                    let ipfilter = data.read().await.ipfilter.clone();
                    if !ip_allowed(&ipfilter, "portforward", &rule_id, &client.ip().to_string()) {
                        eprintln!("[portforward] UDP blocked {} → {listen}", client.ip());
                        continue;
                    }
                }
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
    db: Db,
) {
    let client = Client::new();
    // Run once immediately
    sync_and_record(&client, &rule, &data, &db).await;

    let interval_secs = if rule.interval > 0 {
        rule.interval as u64
    } else {
        300
    };
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(interval_secs)) => {
                sync_and_record(&client, &rule, &data, &db).await;
            }
        }
    }
}

async fn sync_and_record(
    client: &Client,
    rule: &DdnsRule,
    data: &Arc<RwLock<crate::models::RuntimeData>>,
    db: &Db,
) {
    let result = sync_ddns_provider(client, rule).await;
    let at = now_rfc3339();
    let updated_rule = {
        let mut d = data.write().await;
        if let Some(r) = d.ddns.iter_mut().find(|x| x.id == rule.id) {
            match &result {
                Ok(ip) => {
                    r.last_ip = ip.clone();
                    r.last_updated = at.clone();
                    r.last_sync_ok = Some(true);
                    r.last_sync_err.clear();
                    r.last_sync_at = at.clone();
                    r.ip_history.push(IpRecord {
                        ip: ip.clone(),
                        timestamp: at,
                    });
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
            Some(r.clone())
        } else {
            None
        }
    };
    // Persist updated DDNS rule to DB
    if let Some(r) = updated_rule {
        let _ = db.save_ddns(&r).await;
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
        &[
            "https://api.ipify.org",
            "https://ident.me",
            "https://api4.ipify.org",
        ]
    };
    let mut last_err = anyhow::anyhow!("no IP source available");
    for url in urls {
        match client
            .get(*url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
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
    let record_type = if rule.ip_version == "ipv6" {
        "AAAA"
    } else {
        "A"
    };

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
        return Err(anyhow::anyhow!(
            "AliDNS requires access_key_id and access_key_secret"
        ));
    }

    let domains = effective_domains(rule);
    let record_type = if rule.ip_version == "ipv6" {
        "AAAA"
    } else {
        "A"
    };

    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (rr, domain) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("@", fqdn.as_str())
        };

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

pub fn build_aliyun_params<'a>(
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

pub fn sign_aliyun_params(params: &[(String, String)], secret: &str) -> Vec<(String, String)> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let mut sorted = params.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let query_str: String = sorted
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
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
    let record_type = if rule.ip_version == "ipv6" {
        "AAAA"
    } else {
        "A"
    };

    for fqdn in &domains {
        let parts: Vec<&str> = fqdn.splitn(2, '.').collect();
        let (sub, domain) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("@", fqdn.as_str())
        };

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
                    r["type"]
                        .as_str()
                        .map(|t| t == record_type)
                        .unwrap_or(false)
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
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    if secret_id.is_empty() || secret_key.is_empty() {
        return Err(anyhow::anyhow!(
            "Tencent DNS requires secret_id and secret_key"
        ));
    }
    let token = format!("{secret_id},{secret_key}");
    let mut proxy_rule = rule.clone();
    proxy_rule.provider_conf.api_token = token;
    sync_dnspod(client, &proxy_rule, ip).await
}

pub fn effective_domains(rule: &DdnsRule) -> Vec<String> {
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

// ─── Web Service (HTTP reverse proxy with optional TLS) ───────────────────────

/// Find the best matching TLS certificate for a domain, supporting wildcards.
pub fn find_tls_cert<'a>(tls_rules: &'a [TlsRule], domain: &str) -> Option<&'a TlsRule> {
    // Prefer active exact match, then active wildcard, then inactive
    let mut best: Option<&TlsRule> = None;
    for cert in tls_rules {
        if cert.cert_pem.is_empty() || cert.key_pem.is_empty() {
            continue;
        }
        let all_domains: Vec<&str> = cert
            .domains
            .iter()
            .map(|s| s.as_str())
            .chain(if cert.domain.is_empty() {
                None
            } else {
                Some(cert.domain.as_str())
            })
            .collect();
        let matched = all_domains.iter().any(|cd| cert_domain_matches(cd, domain));
        if !matched {
            continue;
        }
        match (&best, cert.status.as_str()) {
            (None, _) => best = Some(cert),
            (Some(b), "active") if b.status != "active" => best = Some(cert),
            _ => {}
        }
        if best.map(|b| b.status == "active").unwrap_or(false) {
            break;
        }
    }
    best
}

pub fn cert_domain_matches(cert_domain: &str, req_domain: &str) -> bool {
    let cd = cert_domain.to_lowercase();
    let rd = req_domain.to_lowercase();
    if cd == rd {
        return true;
    }
    if cd.starts_with("*.") {
        let suffix = &cd[1..]; // .example.com
        if rd.ends_with(suffix) {
            let host = &rd[..rd.len() - suffix.len()];
            if !host.contains('.') {
                return true;
            }
        }
    }
    false
}

/// Build a rustls ServerConfig from matched TLS rules for the given set of routes.
pub fn build_tls_config(
    routes: &[WebRoute],
    tls_rules: &[TlsRule],
) -> Option<Arc<rustls::ServerConfig>> {
    use rustls::ServerConfig;

    let mut cert_resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let mut any_added = false;

    for route in routes {
        if !route.enabled || route.domain.is_empty() {
            continue;
        }
        let cert_id = &route.matched_cert_id;
        if cert_id.is_empty() {
            continue;
        }
        let tls_cert = match tls_rules.iter().find(|c| &c.id == cert_id) {
            Some(c) if !c.cert_pem.is_empty() && !c.key_pem.is_empty() => c,
            _ => continue,
        };

        // Helper: build a CertifiedKey by re-parsing PEM each time (CertifiedKey has no Clone)
        let build_ck = |cert_pem: &str, key_pem: &str| -> Option<rustls::sign::CertifiedKey> {
            let chain: Vec<rustls::pki_types::CertificateDer<'static>> = {
                let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
                rustls_pemfile::certs(&mut reader)
                    .filter_map(|r| r.ok())
                    .collect()
            };
            if chain.is_empty() {
                return None;
            }
            let key_der: rustls::pki_types::PrivateKeyDer = {
                let mut reader = std::io::BufReader::new(key_pem.as_bytes());
                let mut found: Option<rustls::pki_types::PrivateKeyDer> = None;
                while let Ok(Some(item)) = rustls_pemfile::read_one(&mut reader) {
                    match item {
                        rustls_pemfile::Item::Pkcs8Key(k) => {
                            found = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(k));
                            break;
                        }
                        rustls_pemfile::Item::Pkcs1Key(k) => {
                            found = Some(rustls::pki_types::PrivateKeyDer::Pkcs1(k));
                            break;
                        }
                        rustls_pemfile::Item::Sec1Key(k) => {
                            found = Some(rustls::pki_types::PrivateKeyDer::Sec1(k));
                            break;
                        }
                        _ => {}
                    }
                }
                found?
            };
            let sk = rustls::crypto::ring::sign::any_supported_type(&key_der).ok()?;
            Some(rustls::sign::CertifiedKey::new(chain, sk))
        };

        let domain = route.domain.to_lowercase();

        if let Some(ck) = build_ck(&tls_cert.cert_pem, &tls_cert.key_pem) {
            let _ = cert_resolver.add(&domain, ck);
            if !domain.starts_with("*.") {
                if let Some(ck2) = build_ck(&tls_cert.cert_pem, &tls_cert.key_pem) {
                    let _ = cert_resolver.add(&format!("www.{domain}"), ck2);
                }
            }
            any_added = true;
        }
    }

    if !any_added {
        return None;
    }

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
    format!(
        r#"<!DOCTYPE html>
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
</html>"#
    )
}

/// Parse browser name from User-Agent (mirrors Go version).
pub fn parse_browser(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();
    if ua_lower.contains("edg/") || ua_lower.contains("edge/") {
        return "Edge".to_string();
    }
    if ua_lower.contains("chrome") && ua_lower.contains("mobile") {
        return "Chrome/Android".to_string();
    }
    if ua_lower.contains("chrome") {
        return "Chrome".to_string();
    }
    if ua_lower.contains("firefox") {
        return "Firefox".to_string();
    }
    if ua_lower.contains("safari") && ua_lower.contains("mobile") {
        return "Safari/iOS".to_string();
    }
    if ua_lower.contains("safari") {
        return "Safari".to_string();
    }
    if ua_lower.contains("curl") {
        return "curl".to_string();
    }
    if ua_lower.contains("wget") {
        return "wget".to_string();
    }
    if ua.is_empty() {
        return "—".to_string();
    }
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
        if !route.enabled {
            continue;
        }
        let route_domain = route.domain.trim_start_matches("www.").to_lowercase();
        let req_domain = host_bare.trim_start_matches("www.");
        if route_domain == req_domain || route.domain.is_empty() {
            return Some((route, true));
        }
    }
    // First enabled route as fallback
    rule.routes
        .iter()
        .find(|r| r.enabled && !r.backend_url.is_empty())
        .map(|r| (r, false))
}

async fn run_webservice(
    svc_id: String,
    listen_port: u16,
    enable_https: bool,
    mut stop: oneshot::Receiver<()>,
    tls_rules: Vec<TlsRule>,
    ipfilter: Vec<IpFilterRule>,
    db: Db,
    data: Arc<RwLock<crate::models::RuntimeData>>,
) {
    use tokio_rustls::TlsAcceptor;

    let addr: SocketAddr = match format!("0.0.0.0:{listen_port}").parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[webservice] invalid port {listen_port}: {e}");
            return;
        }
    };
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[webservice] bind {addr} failed: {e}");
            return;
        }
    };

    // Build initial TLS acceptor from cert snapshot
    let initial_routes: Vec<WebRoute> = {
        let d = data.read().await;
        d.webservice
            .iter()
            .find(|s| s.id == svc_id)
            .map(|s| s.routes.clone())
            .unwrap_or_default()
    };
    let tls_acceptor: Option<TlsAcceptor> = if enable_https {
        build_tls_config(&initial_routes, &tls_rules).map(TlsAcceptor::from)
    } else {
        None
    };

    let _tls_rules = Arc::new(tls_rules);
    let ipfilter = Arc::new(ipfilter);
    let svc_id = Arc::new(svc_id);

    eprintln!(
        "[webservice] {} listening on {addr} (https={enable_https})",
        svc_id
    );

    loop {
        tokio::select! {
            _ = &mut stop => break,
            conn = listener.accept() => {
                let (stream, peer) = match conn { Ok(v) => v, Err(_) => continue };
                let svc_id2   = svc_id.clone();
                let data2     = data.clone();
                let ipf2      = ipfilter.clone();
                let db2       = db.clone();
                let tls2      = tls_acceptor.clone();
                let port      = listen_port;
                tokio::spawn(async move {
                    dispatch_connection(stream, peer, svc_id2, data2, ipf2, db2, tls2, port).await;
                });
            }
        }
    }
    eprintln!("[webservice] {} stopped", svc_id);
}

/// Peek first byte to distinguish TLS from plain HTTP, then dispatch to hyper.
/// Uses a PrefixedStream to safely put the peeked byte back without races.
async fn dispatch_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    svc_id: Arc<String>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    ipfilter: Arc<Vec<IpFilterRule>>,
    db: Db,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    listen_port: u16,
) {
    use tokio::io::AsyncReadExt;
    if let Some(acceptor) = tls_acceptor {
        let mut first_byte = [0u8; 1];
        let n = (&mut stream).read(&mut first_byte).await.unwrap_or(0);
        // Reconstruct the stream with the peeked byte prepended
        let prefixed = PrefixedStream::new(if n == 1 { first_byte[0] } else { 0 }, n == 1, stream);
        if n == 1 && first_byte[0] == 0x16 {
            // TLS ClientHello
            match acceptor.accept(prefixed).await {
                Ok(tls) => serve_hyper_tls(tls, peer, svc_id, data, ipfilter, db, true).await,
                Err(e) => eprintln!("[webservice] TLS accept {peer}: {e}"),
            }
        } else {
            // Plain HTTP → send 301 redirect to HTTPS
            redirect_to_https_async(prefixed, peer, listen_port).await;
        }
    } else {
        serve_hyper_plain(stream, peer, svc_id, data, ipfilter, db).await;
    }
}

/// A stream that prefixes a single peeked byte before delegating to the inner stream.
struct PrefixedStream {
    prefix: u8,
    has_prefix: bool,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: u8, has_prefix: bool, inner: TcpStream) -> Self {
        Self { prefix, has_prefix, inner }
    }
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.has_prefix {
            if buf.remaining() > 0 {
                buf.put_slice(&[self.prefix]);
                self.has_prefix = false;
                return std::task::Poll::Ready(Ok(()));
            }
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Send 301 to HTTPS for plain-HTTP connections on a TLS-enabled service.
async fn redirect_to_https(mut stream: TcpStream, peer: SocketAddr, port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let host = req
        .lines()
        .find(|l| l.to_lowercase().starts_with("host:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .unwrap_or("")
        .trim()
        .to_string();
    let host_bare = host.split(':').next().unwrap_or(&host);
    let location = if port == 443 {
        format!("https://{host_bare}{path}")
    } else {
        format!("https://{host_bare}:{port}{path}")
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = peer;
}

/// Same as redirect_to_https but accepts any AsyncRead+AsyncWrite (e.g. tokio::io::DuplexStream).
async fn redirect_to_https_async<S>(mut stream: S, peer: SocketAddr, port: u16)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let host = req
        .lines()
        .find(|l| l.to_lowercase().starts_with("host:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .unwrap_or("")
        .trim()
        .to_string();
    let host_bare = host.split(':').next().unwrap_or(&host);
    let location = if port == 443 {
        format!("https://{host_bare}{path}")
    } else {
        format!("https://{host_bare}:{port}{path}")
    };
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = peer;
}

// ─── Hyper service context ─────────────────────────────────────────────────────

#[derive(Clone)]
struct ProxyCtx {
    peer: SocketAddr,
    svc_id: Arc<String>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    ipfilter: Arc<Vec<IpFilterRule>>,
    db: Db,
    is_https: bool,
}

async fn serve_hyper_plain(
    stream: TcpStream,
    peer: SocketAddr,
    svc_id: Arc<String>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    ipfilter: Arc<Vec<IpFilterRule>>,
    db: Db,
) {
    let ctx = ProxyCtx {
        peer,
        svc_id,
        data,
        ipfilter,
        db,
        is_https: false,
    };
    let svc = hyper::service::service_fn(move |req| {
        let ctx = ctx.clone();
        async move { proxy_request(req, ctx).await }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
        .with_upgrades() // ← enables WebSocket upgrade
        .await
    {
        if !is_benign_hyper_error(&e) {
            eprintln!("[webservice] hyper plain conn error: {e}");
        }
    }
}

async fn serve_hyper_tls<S>(
    stream: tokio_rustls::server::TlsStream<S>,
    peer: SocketAddr,
    svc_id: Arc<String>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    ipfilter: Arc<Vec<IpFilterRule>>,
    db: Db,
    is_https: bool,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ctx = ProxyCtx {
        peer,
        svc_id,
        data,
        ipfilter,
        db,
        is_https,
    };
    let svc = hyper::service::service_fn(move |req| {
        let ctx = ctx.clone();
        async move { proxy_request(req, ctx).await }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
        .with_upgrades()
        .await
    {
        if !is_benign_hyper_error(&e) {
            eprintln!("[webservice] hyper tls conn error: {e}");
        }
    }
}

fn is_benign_hyper_error(e: &hyper::Error) -> bool {
    // connection reset / client hangup are normal
    e.is_incomplete_message() || e.is_canceled() || e.is_closed()
}

// ─── Core reverse-proxy request handler ──────────────────────────────────────

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

async fn proxy_request(
    req: hyper::Request<hyper::body::Incoming>,
    ctx: ProxyCtx,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    Ok(proxy_request_inner(req, ctx).await)
}

async fn proxy_request_inner(
    req: hyper::Request<hyper::body::Incoming>,
    ctx: ProxyCtx,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Response, StatusCode};

    let client_ip = ctx.peer.ip().to_string();

    // ── Live route + ipfilter snapshot ────────────────────────────────────
    let (svc_snap, ipf_live) = {
        let d = ctx.data.read().await;
        let svc = d.webservice.iter().find(|s| s.id == *ctx.svc_id).cloned();
        let ipf = d.ipfilter.clone();
        (svc, ipf)
    };
    let svc_snap = match svc_snap {
        Some(s) => Arc::new(s),
        None => return bad_gateway("service not found"),
    };
    let ipfilter = if !ipf_live.is_empty() {
        Arc::new(ipf_live)
    } else {
        ctx.ipfilter.clone()
    };

    // ── Route matching ─────────────────────────────────────────────────────
    let host_header = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let matched_route = match find_route_for_request(&svc_snap, &host_header) {
        Some((r, _)) => r.clone(),
        None => return bad_gateway(&format!("no route for host: {host_header}")),
    };

    // ── IP filter ──────────────────────────────────────────────────────────
    if !ip_allowed(&ipfilter, "webservice", &matched_route.id, &client_ip) {
        return simple_response(StatusCode::FORBIDDEN, "Forbidden");
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // ── Auth check (cookie-based) ──────────────────────────────────────────
    if matched_route.auth_enabled && !matched_route.auth_pass_hash.is_empty() {
        let cookie_name = format!(
            "vane_auth_{}",
            &matched_route.id[..8.min(matched_route.id.len())]
        );
        let session_token = auth_session_token(&matched_route.id, &matched_route.auth_pass_hash);
        let cookie_ok = req
            .headers()
            .get_all("cookie")
            .iter()
            .flat_map(|v| v.to_str().unwrap_or("").split(';'))
            .any(|c| {
                let c = c.trim();
                c.split_once('=')
                    .map(|(k, v)| k.trim() == cookie_name && v.trim() == session_token)
                    .unwrap_or(false)
            });

        if !cookie_ok {
            if req.method() == Method::POST && path == "/__vane_login__" {
                let body_bytes = req.collect().await.unwrap_or_default().to_bytes();
                let form = String::from_utf8_lossy(&body_bytes);
                let (mut user, mut pass, mut next) =
                    (String::new(), String::new(), "/".to_string());
                for part in form.split('&') {
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
                if next.is_empty() {
                    next = "/".to_string();
                }
                let ok = user == matched_route.auth_user
                    && bcrypt::verify(&pass, &matched_route.auth_pass_hash).unwrap_or(false);
                if ok {
                    let sf = if ctx.is_https { "; Secure" } else { "" };
                    let sc = format!("{cookie_name}={session_token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax{sf}");
                    return Response::builder()
                        .status(StatusCode::FOUND)
                        .header("Location", next)
                        .header("Set-Cookie", sc)
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                } else {
                    let page = build_login_page(&path, "用户名或密码错误", &matched_route.domain);
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(Full::new(Bytes::from(page)))
                        .unwrap();
                }
            }
            log_access_async(
                &ctx.db,
                &ctx.svc_id,
                &matched_route,
                &client_ip,
                &user_agent,
                "no_auth",
            )
            .await;
            let page = build_login_page(&path, "", &matched_route.domain);
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(page)))
                .unwrap();
        }
    }

    // ── Build upstream URL ─────────────────────────────────────────────────
    let backend_raw = matched_route.backend_url.trim_end_matches('/');
    if backend_raw.is_empty() {
        return bad_gateway("empty backend");
    }
    let (upstream_base, backend_prefix) = parse_backend_base(backend_raw);
    let upstream_path = if backend_prefix.is_empty() {
        path.clone()
    } else {
        format!("{backend_prefix}{path}")
    };
    let upstream_url = format!("{upstream_base}{upstream_path}");

    let method = req.method().clone();
    let req_headers = req.headers().clone();

    // ── WebSocket upgrade ──────────────────────────────────────────────────
    let is_upgrade = req_headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase() == "websocket")
        .unwrap_or(false);

    if is_upgrade {
        log_access_async(
            &ctx.db,
            &ctx.svc_id,
            &matched_route,
            &client_ip,
            &user_agent,
            "websocket",
        )
        .await;
        return ws_tunnel(
            req,
            &upstream_base,
            &upstream_path,
            &client_ip,
            ctx.is_https,
        )
        .await;
    }

    // ── HTTP reverse proxy via hyper client ───────────────────────────────
    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return bad_gateway("read request body failed"),
    };

    // Use reqwest for upstream (handles TLS, HTTP/2, redirects, timeouts out of the box)
    static UPSTREAM_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let upstream_client = UPSTREAM_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build upstream client")
    });

    let mut req_builder = upstream_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        &upstream_url,
    );
    for (k, v) in &req_headers {
        let key = k.as_str();
        if HOP_BY_HOP.contains(&key) {
            continue;
        }
        req_builder = req_builder.header(k, v);
    }
    req_builder = req_builder
        .header("host", &host_header)
        .header("x-forwarded-for", &client_ip)
        .header("x-real-ip", &client_ip)
        .header("x-forwarded-host", &host_header)
        .header(
            "x-forwarded-proto",
            if ctx.is_https { "https" } else { "http" },
        )
        .body(body_bytes.to_vec());

    match req_builder.send().await {
        Ok(resp) => {
            let status = hyper::StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(hyper::StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            for (k, v) in resp.headers() {
                if HOP_BY_HOP.contains(&k.as_str()) {
                    continue;
                }
                builder = builder.header(k.as_str(), v.as_bytes());
            }
            let body = resp.bytes().await.unwrap_or_default();
            let http_status_code = resp.status().as_u16();
            log_access_async_with_status(
                &ctx.db,
                &ctx.svc_id,
                &matched_route,
                &client_ip,
                &user_agent,
                "ok",
                http_status_code,
            )
            .await;
            builder
                .body(Full::new(Bytes::from(body)))
                .unwrap_or_else(|_| bad_gateway("response build"))
        }
        Err(e) => {
            eprintln!("[webservice] upstream error {upstream_url}: {e}");
            bad_gateway(&format!("upstream: {e}"))
        }
    }
}

// ─── WebSocket tunnel ─────────────────────────────────────────────────────────

async fn ws_tunnel(
    req: hyper::Request<hyper::body::Incoming>,
    upstream_base: &str,
    upstream_path: &str,
    client_ip: &str,
    _is_https: bool,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    use hyper::header::{CONNECTION, UPGRADE};

    // Resolve backend host:port from upstream_base (e.g. "http://127.0.0.1:8080")
    let backend_host = upstream_base
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    // Collect all original WS headers to forward to backend
    let mut extra_headers = String::new();
    for (k, v) in req.headers() {
        let key = k.as_str().to_lowercase();
        if key == "host" || key == "connection" || key == "upgrade" {
            continue;
        }
        if let Ok(val) = v.to_str() {
            extra_headers.push_str(&format!("{}: {}\r\n", k.as_str(), val));
        }
    }

    let upgraded_client = hyper::upgrade::on(req);
    let backend_host2 = backend_host.clone();
    let upstream_path2 = upstream_path.to_string();
    let client_ip2 = client_ip.to_string();

    tokio::spawn(async move {
        match upgraded_client.await {
            Ok(client_io) => {
                match TcpStream::connect(&backend_host2).await {
                    Ok(mut backend) => {
                        use tokio::io::AsyncWriteExt;
                        // Forward the proper WS handshake preserving all original headers
                        let handshake = format!(
                            "GET {upstream_path2} HTTP/1.1\r\nHost: {backend_host2}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Forwarded-For: {client_ip2}\r\nX-Real-IP: {client_ip2}\r\n{extra_headers}\r\n"
                        );
                        let _ = backend.write_all(handshake.as_bytes()).await;
                        // Bidirectional copy
                        let mut client_io = hyper_util::rt::TokioIo::new(client_io);
                        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut backend).await;
                    }
                    Err(e) => eprintln!("[webservice] ws backend connect {backend_host2}: {e}"),
                }
            }
            Err(e) => eprintln!("[webservice] ws upgrade: {e}"),
        }
    });

    hyper::Response::builder()
        .status(hyper::StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn bad_gateway(msg: &str) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    simple_response(hyper::StatusCode::BAD_GATEWAY, msg)
}

fn simple_response(
    status: hyper::StatusCode,
    body: &str,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            body.to_string(),
        )))
        .unwrap()
}

/// Parse backend URL into (scheme://host[:port], /path/prefix)
fn parse_backend_base(backend: &str) -> (String, String) {
    if let Ok(u) = url::Url::parse(backend) {
        let path = u.path().trim_end_matches('/').to_string();
        let host = u.host_str().unwrap_or("");
        let base = if let Some(port) = u.port() {
            format!("{}://{}:{}", u.scheme(), host, port)
        } else {
            format!("{}://{}", u.scheme(), host)
        };
        (base, path)
    } else {
        (backend.to_string(), String::new())
    }
}

/// Deduplicated access-log writer (today + routeID + clientIP + browser).
async fn log_access_async(
    db: &Db,
    service_id: &str,
    route: &WebRoute,
    client_ip: &str,
    ua: &str,
    auth_result: &str,
) {
    log_access_async_with_status(db, service_id, route, client_ip, ua, auth_result, 0).await;
}

async fn log_access_async_with_status(
    db: &Db,
    service_id: &str,
    route: &WebRoute,
    client_ip: &str,
    ua: &str,
    auth_result: &str,
    status_code: u16,
) {
    use std::collections::HashSet;
    use std::sync::Mutex;
    // Dedup store: keys are "YYYY-MM-DD\x00routeID\x00clientIP\x00browser"
    // We track the last-seen date and flush the set when the day rolls over.
    static SEEN: std::sync::OnceLock<Mutex<(String, HashSet<String>)>> = std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new((String::new(), HashSet::new())));
    let browser = parse_browser(ua);
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let key = format!("{today}\x00{}\x00{client_ip}\x00{browser}", route.id);
    let is_new = seen.lock().map(|mut guard| {
        let (ref mut last_day, ref mut set) = *guard;
        // Clear on day rollover
        if *last_day != today {
            set.clear();
            *last_day = today.clone();
        }
        if set.len() > 100_000 {
            set.clear();
        }
        set.insert(key)
    }).unwrap_or(true);
    if !is_new {
        return;
    }
    let log = crate::models::AccessLog {
        id: crate::state::new_id(),
        service_id: service_id.to_string(),
        route_id: route.id.clone(),
        route_name: route.name.clone(),
        domain: route.domain.clone(),
        status_code,
        client_ip: client_ip.to_string(),
        user_agent: browser,
        auth_result: auth_result.to_string(),
        time: now_rfc3339(),
    };
    let _ = db.append_access_log(&log).await;
}

/// Check client IP against ip-filter rules.
fn ip_allowed(rules: &[IpFilterRule], scope_type: &str, target_id: &str, client_ip: &str) -> bool {
    let ip: Option<std::net::IpAddr> = client_ip.parse().ok();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let ok = rule.scopes.iter().any(|s| {
            s.scope_type == scope_type && (s.target_id.is_empty() || s.target_id == target_id)
        });
        if !ok {
            continue;
        }
        let mut all: Vec<&str> = rule.manual_ips.iter().map(String::as_str).collect();
        for att in &rule.attachments {
            all.extend(att.ips.iter().map(String::as_str));
        }
        let matched = ip_in_list(&ip, client_ip, &all);
        return if rule.mode == "blacklist" {
            !matched
        } else {
            matched
        };
    }
    true
}

fn ip_in_list(ip: &Option<std::net::IpAddr>, raw: &str, list: &[&str]) -> bool {
    for e in list {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        if let Ok(net) = e.parse::<ipnet::IpNet>() {
            if let Some(a) = ip {
                if net.contains(a) {
                    return true;
                }
            }
        } else if e == raw {
            return true;
        } else if let (Some(a), Ok(b)) = (ip, e.parse::<std::net::IpAddr>()) {
            if *a == b {
                return true;
            }
        }
    }
    false
}

// ─── TLS auto-renew watcher ───────────────────────────────────────────────────

async fn run_tls_autorenew(
    rule: TlsRule,
    mut stop: oneshot::Receiver<()>,
    data: Arc<RwLock<crate::models::RuntimeData>>,
    db: Db,
) {
    // First check after 1 hour, then every 12 hours
    tokio::time::sleep(Duration::from_secs(3600)).await;
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(12 * 3600)) => {}
        }
        if !rule.auto_renew {
            continue;
        }
        let days = rule.days_until_expiry();
        if days >= 0 && days <= 30 {
            eprintln!(
                "[tls] cert {} expiring in {days} days, auto-renewing",
                rule.id
            );
            match crate::acme::issue_cert(&rule).await {
                Ok((cert_pem, key_pem, issued_at, expires_at)) => {
                    let updated = {
                        let mut d = data.write().await;
                        if let Some(x) = d.tls.iter_mut().find(|x| x.id == rule.id) {
                            x.cert_pem = cert_pem;
                            x.key_pem = key_pem;
                            x.issued_at = issued_at;
                            x.expires_at = expires_at;
                            x.status = "active".to_string();
                            x.error_msg.clear();
                            Some(x.clone())
                        } else {
                            None
                        }
                    };
                    if let Some(cert) = updated {
                        let _ = db.save_tls_cert(&cert).await;
                    }
                }
                Err(e) => {
                    eprintln!("[tls] auto-renew {} failed: {e}", rule.id);
                    let updated = {
                        let mut d = data.write().await;
                        if let Some(x) = d.tls.iter_mut().find(|x| x.id == rule.id) {
                            x.status = "error".to_string();
                            x.error_msg = e.to_string();
                            Some(x.clone())
                        } else {
                            None
                        }
                    };
                    if let Some(cert) = updated {
                        let _ = db.save_tls_cert(&cert).await;
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
                    route.cert_status = if cert.status == "active" {
                        "ok".to_string()
                    } else {
                        "cert_inactive".to_string()
                    };
                }
                None => {
                    route.matched_cert_id.clear();
                    route.cert_status = "no_cert".to_string();
                }
            }
        }
    }
}

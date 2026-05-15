use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use reqwest::Client;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
    sync::{oneshot, RwLock},
    time,
};

use crate::models::{DdnsRule, PortForwardRule, TlsRule, WebServiceRule};

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
            |r, rx| tokio::spawn(run_forwarder(r, rx)),
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
            |r, rx| tokio::spawn(run_ddns(r, rx)),
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
            |r, rx| tokio::spawn(run_webservice(r, rx)),
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
            |r, rx| tokio::spawn(run_tls(r, rx)),
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

async fn run_forwarder(rule: PortForwardRule, mut stop: oneshot::Receiver<()>) {
    if !rule.protocol.eq_ignore_ascii_case("tcp") {
        return;
    }
    let listen: SocketAddr = match rule.listen.parse() {
        Ok(v) => v,
        Err(_) => return,
    };
    let target: SocketAddr = match rule.target.parse() {
        Ok(v) => v,
        Err(_) => return,
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(v) => v,
        Err(_) => return,
    };
    loop {
        tokio::select! { _ = &mut stop => break, c = listener.accept() => { if let Ok((inbound,_)) = c { tokio::spawn(proxy_tcp(inbound, target)); } } }
    }
}

async fn proxy_tcp(mut inbound: TcpStream, target: SocketAddr) {
    if let Ok(mut outbound) = TcpStream::connect(target).await {
        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
    }
}

async fn run_ddns(rule: DdnsRule, mut stop: oneshot::Receiver<()>) {
    let client = Client::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(300)) => {
                let _ = sync_cloudflare(&client, &rule).await;
            }
        }
    }
}

async fn sync_cloudflare(client: &Client, rule: &DdnsRule) -> anyhow::Result<()> {
    if !rule.provider.eq_ignore_ascii_case("cloudflare")
        || rule.token.is_empty()
        || rule.zone.is_empty()
        || rule.record_name.is_empty()
    {
        return Ok(());
    }
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .await?
        .text()
        .await?;
    let recs: serde_json::Value = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type={}&name={}",
            rule.zone, rule.record_type, rule.record_name
        ))
        .bearer_auth(&rule.token)
        .send()
        .await?
        .json()
        .await?;
    let rid = recs
        .get("result")
        .and_then(|r| r.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.get("id"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    if rid.is_empty() {
        return Ok(());
    }
    let body = serde_json::json!({"type": rule.record_type, "name": rule.record_name, "content": ip.trim(), "proxied": rule.proxied});
    let _resp: serde_json::Value = client
        .put(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            rule.zone, rid
        ))
        .bearer_auth(&rule.token)
        .json(&body)
        .send()
        .await?
        .json()
        .await?;
    Ok(())
}

async fn run_webservice(rule: WebServiceRule, mut stop: oneshot::Receiver<()>) {
    let listen: SocketAddr = match rule.listen.parse() {
        Ok(v) => v,
        Err(_) => return,
    };
    let backend: SocketAddr = match rule.backend.parse() {
        Ok(v) => v,
        Err(_) => return,
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(v) => v,
        Err(_) => return,
    };
    loop {
        tokio::select! { _=&mut stop => break, c=listener.accept()=>{ if let Ok((inbound,_))=c { tokio::spawn(proxy_tcp(inbound, backend)); } } }
    }
}

async fn run_tls(rule: TlsRule, mut stop: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(3600)) => {
                let _ = tokio::fs::metadata(&rule.cert_path).await;
                let _ = tokio::fs::metadata(&rule.key_path).await;
            }
        }
    }
}

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

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
        reconcile_tasks(
            &self.portforward,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.id.clone())
                .collect(),
        )
        .await;

        for r in rules.iter().filter(|r| r.enabled) {
            let mut m = self.portforward.write().await;
            if m.contains_key(&r.id) {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            m.insert(r.id.clone(), tx);
            tokio::spawn(run_forwarder(r.clone(), rx));
        }
    }

    pub async fn apply_ddns(&self, rules: &[DdnsRule]) {
        reconcile_tasks(
            &self.ddns,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.id.clone())
                .collect(),
        )
        .await;
        for r in rules.iter().filter(|r| r.enabled) {
            let mut m = self.ddns.write().await;
            if m.contains_key(&r.id) {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            m.insert(r.id.clone(), tx);
            tokio::spawn(run_ddns(r.clone(), rx));
        }
    }

    pub async fn apply_webservice(&self, rules: &[WebServiceRule]) {
        reconcile_tasks(
            &self.webservice,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.id.clone())
                .collect(),
        )
        .await;
        for r in rules.iter().filter(|r| r.enabled) {
            let mut m = self.webservice.write().await;
            if m.contains_key(&r.id) {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            m.insert(r.id.clone(), tx);
            tokio::spawn(run_webservice(r.clone(), rx));
        }
    }

    pub async fn apply_tls(&self, rules: &[TlsRule]) {
        reconcile_tasks(
            &self.tls,
            rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| r.id.clone())
                .collect(),
        )
        .await;
        for r in rules.iter().filter(|r| r.enabled) {
            let mut m = self.tls.write().await;
            if m.contains_key(&r.id) {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            m.insert(r.id.clone(), tx);
            tokio::spawn(run_tls(r.clone(), rx));
        }
    }
}

async fn reconcile_tasks(
    map: &Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
    enabled: Vec<String>,
) {
    let enabled: std::collections::HashSet<_> = enabled.into_iter().collect();
    let mut m = map.write().await;
    let existing: Vec<String> = m.keys().cloned().collect();
    for id in existing {
        if !enabled.contains(&id) {
            if let Some(tx) = m.remove(&id) {
                let _ = tx.send(());
            }
        }
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
        tokio::select! {
            _ = &mut stop => break,
            c = listener.accept() => {
                let Ok((inbound,_)) = c else { continue; };
                tokio::spawn(proxy_tcp(inbound, target));
            }
        }
    }
}

async fn proxy_tcp(mut inbound: TcpStream, target: SocketAddr) {
    if let Ok(mut outbound) = TcpStream::connect(target).await {
        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
    }
}

async fn run_ddns(_rule: DdnsRule, mut stop: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(300)) => {
                // placeholder for provider API sync
            }
        }
    }
}

async fn run_webservice(_rule: WebServiceRule, mut stop: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(300)) => {
                // placeholder for reverse proxy runtime
            }
        }
    }
}

async fn run_tls(_rule: TlsRule, mut stop: oneshot::Receiver<()>) {
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = time::sleep(Duration::from_secs(3600)) => {
                // placeholder for renewal/health-check loop
            }
        }
    }
}

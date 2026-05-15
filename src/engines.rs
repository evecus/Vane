use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::{
    io,
    net::{TcpListener, TcpStream},
    sync::{oneshot, RwLock},
};

use crate::models::{DdnsRule, PortForwardRule, TlsRule, WebServiceRule};

#[derive(Default, Clone)]
pub struct RuntimeEngines {
    pub portforward: Arc<RwLock<HashMap<String, oneshot::Sender<()>>>>,
}

impl RuntimeEngines {
    pub async fn apply_portforwards(&self, rules: &[PortForwardRule]) {
        let mut map = self.portforward.write().await;
        let enabled: HashMap<_, _> = rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| (r.id.clone(), r.clone()))
            .collect();

        let existing: Vec<String> = map.keys().cloned().collect();
        for id in existing {
            if !enabled.contains_key(&id) {
                if let Some(tx) = map.remove(&id) {
                    let _ = tx.send(());
                }
            }
        }

        for (id, rule) in enabled {
            if map.contains_key(&id) {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            map.insert(id, tx);
            tokio::spawn(run_forwarder(rule, rx));
        }
    }
}

async fn run_forwarder(rule: PortForwardRule, mut stop: oneshot::Receiver<()>) {
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

pub async fn run_ddns(_rules: Vec<DdnsRule>) {}
pub async fn run_webservice(_rules: Vec<WebServiceRule>) {}
pub async fn run_tls(_rules: Vec<TlsRule>) {}

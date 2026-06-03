use crate::config::{Config, PortForwardRule};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::{error, info, warn};

// ─── Stats ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct StatSnapshot {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub conns: i64,
    pub time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Default)]
struct Stats {
    bytes_in: std::sync::atomic::AtomicI64,
    bytes_out: std::sync::atomic::AtomicI64,
    conns: std::sync::atomic::AtomicI64,
}

impl Stats {
    fn snapshot(&self) -> StatSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        StatSnapshot {
            bytes_in: self.bytes_in.load(Relaxed),
            bytes_out: self.bytes_out.load(Relaxed),
            conns: self.conns.load(Relaxed),
            time: chrono::Utc::now(),
        }
    }
}

// ─── Manager ──────────────────────────────────────────────────────────────────

type StopTx = watch::Sender<bool>;

struct WorkerEntry {
    stop: Vec<StopTx>,
    stats: Arc<Stats>,
}

pub struct Manager {
    cfg: Config,
    inner: Mutex<ManagerInner>,
}

#[derive(Default)]
struct ManagerInner {
    workers: HashMap<String, WorkerEntry>,
    history: HashMap<String, Vec<StatSnapshot>>,
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: Mutex::new(ManagerInner::default()),
        })
    }

    pub fn start_all(self: &Arc<Self>) {
        let rules: Vec<PortForwardRule> = {
            let cfg = self.cfg.read();
            cfg.port_forwards
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect()
        };
        for rule in rules {
            if let Err(e) = self.start(&rule.id) {
                error!("[portforward] start {} error: {}", rule.id, e);
            }
        }
        let mgr = Arc::clone(self);
        tokio::spawn(async move { mgr.collect_stats().await });
    }

    pub fn start(self: &Arc<Self>, id: &str) -> anyhow::Result<()> {
        let rule = {
            let cfg = self.cfg.read();
            cfg.port_forwards.iter().find(|r| r.id == id).cloned()
        };
        let rule = rule.ok_or_else(|| anyhow::anyhow!("rule {} not found", id))?;

        // Stop existing
        self.stop(id);

        let stats = Arc::new(Stats::default());
        let mut stops = Vec::new();

        let protocols: Vec<&str> = match rule.protocol.as_str() {
            "both" => vec!["tcp", "udp"],
            "udp" => vec!["udp"],
            _ => vec!["tcp"],
        };

        for proto in protocols {
            let (tx, rx) = watch::channel(false);
            stops.push(tx);
            let r = rule.clone();
            let st = Arc::clone(&stats);
            let cfg = self.cfg.clone();
            let p = proto.to_string();
            tokio::spawn(async move {
                if p == "udp" {
                    run_udp(r, st, rx, cfg).await;
                } else {
                    run_tcp(r, st, rx, cfg).await;
                }
            });
        }

        let mut inner = self.inner.lock().unwrap();
        inner
            .workers
            .insert(id.to_string(), WorkerEntry { stop: stops, stats });
        Ok(())
    }

    pub fn stop(&self, id: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.workers.remove(id) {
            for tx in entry.stop {
                let _ = tx.send(true);
            }
        }
    }

    pub fn get_stats(&self, id: &str) -> Option<StatSnapshot> {
        let inner = self.inner.lock().unwrap();
        inner.workers.get(id).map(|e| e.stats.snapshot())
    }

    pub fn get_history(&self, id: &str) -> Vec<StatSnapshot> {
        let inner = self.inner.lock().unwrap();
        inner.history.get(id).cloned().unwrap_or_default()
    }

    async fn collect_stats(&self) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let mut inner = self.inner.lock().unwrap();
            let ids: Vec<String> = inner.workers.keys().cloned().collect();
            for id in ids {
                if let Some(entry) = inner.workers.get(&id) {
                    let snap = entry.stats.snapshot();
                    let h = inner.history.entry(id).or_default();
                    h.push(snap);
                    if h.len() > 360 {
                        let drain_to = h.len() - 360;
                        h.drain(0..drain_to);
                    }
                }
            }
        }
    }
}

// ─── TCP worker ───────────────────────────────────────────────────────────────

async fn run_tcp(
    rule: PortForwardRule,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
    cfg: Config,
) {
    let addr = format!("0.0.0.0:{}", rule.listen_port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("[portforward] TCP listen {} error: {}", addr, e);
            return;
        }
    };
    info!(
        "[portforward] TCP {} → {}:{}",
        addr, rule.target_ip, rule.target_port
    );

    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { break; } }
            res = listener.accept() => {
                match res {
                    Ok((conn, peer)) => {
                        let client_ip = peer.ip().to_string();
                        if !cfg.check_ip_allowed("portforward", &rule.id, &client_ip) {
                            warn!("[portforward] TCP blocked {} → port {}", client_ip, rule.listen_port);
                            continue;
                        }
                        let target = format!("{}:{}", rule.target_ip, rule.target_port);
                        let st = Arc::clone(&stats);
                        tokio::spawn(async move {
                            handle_tcp(conn, target, st).await;
                        });
                    }
                    Err(e) => { error!("[portforward] TCP accept error: {}", e); }
                }
            }
        }
    }
}

async fn handle_tcp(src: TcpStream, target: String, stats: Arc<Stats>) {
    use std::sync::atomic::Ordering::Relaxed;
    stats.conns.fetch_add(1, Relaxed);
    let st_guard = Arc::clone(&stats);
    scopeguard::defer! { st_guard.conns.fetch_sub(1, Relaxed); }

    let dst = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            error!("[portforward] TCP dial {} error: {}", target, e);
            return;
        }
        Err(_) => {
            error!("[portforward] TCP dial {} timeout", target);
            return;
        }
    };

    let (mut src_r, mut src_w) = src.into_split();
    let (mut dst_r, mut dst_w) = dst.into_split();
    let st1 = Arc::clone(&stats);
    let st2 = Arc::clone(&stats);
    let t1 = tokio::spawn(async move {
        let n = io::copy(&mut src_r, &mut dst_w).await.unwrap_or(0);
        st1.bytes_in.fetch_add(n as i64, Relaxed);
    });
    let t2 = tokio::spawn(async move {
        let n = io::copy(&mut dst_r, &mut src_w).await.unwrap_or(0);
        st2.bytes_out.fetch_add(n as i64, Relaxed);
    });
    let _ = tokio::join!(t1, t2);
}

// ─── UDP worker ───────────────────────────────────────────────────────────────

async fn run_udp(
    rule: PortForwardRule,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
    cfg: Config,
) {
    let addr = format!("0.0.0.0:{}", rule.listen_port);
    let sock = match UdpSocket::bind(&addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("[portforward] UDP bind {} error: {}", addr, e);
            return;
        }
    };
    info!(
        "[portforward] UDP {} → {}:{}",
        addr, rule.target_ip, rule.target_port
    );

    let target = format!("{}:{}", rule.target_ip, rule.target_port);
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = stop.changed() => { if *stop.borrow() { break; } }
            res = sock.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer)) => {
                        let client_ip = peer.ip().to_string();
                        if !cfg.check_ip_allowed("portforward", &rule.id, &client_ip) {
                            warn!("[portforward] UDP blocked {} → port {}", client_ip, rule.listen_port);
                            continue;
                        }
                        use std::sync::atomic::Ordering::Relaxed;
                        stats.bytes_in.fetch_add(n as i64, Relaxed);
                        let data = buf[..n].to_vec();
                        let src = Arc::clone(&sock);
                        let tgt = target.clone();
                        let st = Arc::clone(&stats);
                        tokio::spawn(async move {
                            handle_udp(src, peer, tgt, data, st).await;
                        });
                    }
                    Err(e) => { error!("[portforward] UDP recv error: {}", e); }
                }
            }
        }
    }
}

async fn handle_udp(
    src: Arc<UdpSocket>,
    client: std::net::SocketAddr,
    target: String,
    data: Vec<u8>,
    stats: Arc<Stats>,
) {
    let dst = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };
    if dst.send_to(&data, &target).await.is_err() {
        return;
    }
    let mut resp = vec![0u8; 65535];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), dst.recv(&mut resp))
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|n| {
            use std::sync::atomic::Ordering::Relaxed;
            stats.bytes_out.fetch_add(n as i64, Relaxed);
            let data = resp[..n].to_vec();
            tokio::spawn(async move {
                let _ = src.send_to(&data, client).await;
            });
        });
}

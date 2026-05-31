use crate::config::{Config, TlsCert, WebRoute, WebService};
use anyhow::{anyhow, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn box_body<B>(b: B) -> BoxBody
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<hyper::Error>,
{
    b.map_err(|e| e.into()).boxed()
}

fn full_body(s: impl Into<Bytes>) -> BoxBody {
    Full::new(s.into()).map_err(|_| unreachable!()).boxed()
}

// ─── Access log ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, serde::Serialize)]
pub struct AccessLog {
    pub service_id: String,
    pub route_id: String,
    pub route_name: String,
    pub domain: String,
    pub client_ip: String,
    pub user_agent: String,
    pub time: String,
}

#[derive(Default)]
pub(crate) struct LogStore {
    logs: Vec<AccessLog>,
    dedup: HashMap<String, ()>,
}

impl LogStore {
    fn add(&mut self, log: AccessLog) {
        let today = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Format as YYYY-MM-DD (approximate, UTC)
            let days = now / 86400;
            let ymd = days_to_ymd(days);
            format!("{:04}-{:02}-{:02}", ymd.0, ymd.1, ymd.2)
        };

        // Remove old logs
        self.logs.retain(|l| l.time.starts_with(&today));

        let key = format!("{}\x00{}\x00{}\x00{}", today, log.route_id, log.client_ip, log.user_agent);
        if self.dedup.contains_key(&key) { return; }
        self.dedup.insert(key, ());
        self.logs.push(log);
        if self.logs.len() > 2000 {
            let len = self.logs.len();
            self.logs.drain(0..len - 2000);
        }
    }

    fn list(&self, service_id: &str, limit: usize) -> Vec<AccessLog> {
        self.logs.iter().rev()
            .filter(|l| service_id.is_empty() || l.service_id == service_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simple approximation from unix days
    let y400 = days / 146097;
    let d = days % 146097;
    let y100 = (d / 36524).min(3);
    let d = d - y100 * 36524;
    let y4 = d / 1461;
    let d = d % 1461;
    let y1 = (d / 365).min(3);
    let d = d - y1 * 365;
    let year = y400 * 400 + y100 * 100 + y4 * 4 + y1 + 1970;
    let month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    let mut rem = d;
    for &md in &month_days {
        if rem < md { break; }
        rem -= md;
        month += 1;
    }
    (year, month, rem + 1)
}

// ─── Manager ──────────────────────────────────────────────────────────────────

struct ServiceHandle {
    stop: watch::Sender<bool>,
}

pub struct Manager {
    cfg: Config,
    handles: Mutex<HashMap<String, ServiceHandle>>,
    pub logs: Arc<Mutex<LogStore>>,
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            handles: Mutex::new(HashMap::new()),
            logs: Arc::new(Mutex::new(LogStore::default())),
        })
    }

    pub fn start_all(self: &Arc<Self>) {
        let svcs: Vec<WebService> = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().filter(|s| s.enabled).cloned().collect()
        };
        for svc in svcs {
            if let Err(e) = self.start(&svc.id) {
                error!("[webservice] start {} error: {}", svc.id, e);
            }
        }
    }

    pub fn start(self: &Arc<Self>, id: &str) -> Result<()> {
        let svc = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().find(|s| s.id == id).cloned()
        };
        let svc = svc.ok_or_else(|| anyhow!("service {} not found", id))?;
        self.stop(id);

        let (tx, rx) = watch::channel(false);
        let mgr = Arc::clone(self);
        let svc_id = id.to_string();
        tokio::spawn(async move { mgr.run_service(svc, rx, svc_id).await; });
        self.handles.lock().unwrap().insert(id.to_string(), ServiceHandle { stop: tx });
        Ok(())
    }

    pub fn stop(&self, id: &str) {
        if let Some(h) = self.handles.lock().unwrap().remove(id) {
            let _ = h.stop.send(true);
        }
    }

    pub fn get_logs(&self, service_id: &str, limit: usize) -> Vec<AccessLog> {
        self.logs.lock().unwrap().list(service_id, limit)
    }

    async fn run_service(self: Arc<Self>, svc: WebService, mut stop: watch::Receiver<bool>, svc_id: String) {
        let addr = format!("0.0.0.0:{}", svc.listen_port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => { error!("[webservice] bind {} error: {}", addr, e); return; }
        };
        info!("[webservice] listening on {} (https={})", addr, svc.enable_https);

        loop {
            tokio::select! {
                _ = stop.changed() => { if *stop.borrow() { break; } }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let mgr = Arc::clone(&self);
                            let id = svc_id.clone();
                            tokio::spawn(async move {
                                mgr.handle_conn(stream, peer, &id).await;
                            });
                        }
                        Err(e) => { error!("[webservice] accept error: {}", e); }
                    }
                }
            }
        }
    }

    async fn handle_conn(self: &Arc<Self>, stream: TcpStream, peer: SocketAddr, svc_id: &str) {
        let client_ip = peer.ip().to_string();
        let svc = {
            let cfg = self.cfg.read();
            cfg.web_services.iter().find(|s| s.id == svc_id).cloned()
        };
        let Some(svc) = svc else { return };

        if svc.enable_https {
            let mut peek_buf = [0u8; 1];
            if stream.peek(&mut peek_buf).await.is_err() { return; }

            if peek_buf[0] == 0x16 {
                let tls_config = self.build_tls_config(svc_id);
                match tls_config {
                    Some(config) => {
                        let acceptor = TlsAcceptor::from(config);
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                self.serve_http(hyper_util::rt::TokioIo::new(tls_stream), &client_ip, svc_id, true).await;
                            }
                            Err(e) => { warn!("[webservice] TLS accept error from {}: {}", client_ip, e); }
                        }
                    }
                    None => { warn!("[webservice] no TLS config for {}", svc_id); }
                }
            } else {
                self.serve_redirect(stream, svc.listen_port).await;
            }
        } else {
            self.serve_http(hyper_util::rt::TokioIo::new(stream), &client_ip, svc_id, false).await;
        }
    }

    fn build_tls_config(&self, svc_id: &str) -> Option<Arc<ServerConfig>> {
        let cfg = self.cfg.read();
        let svc = cfg.web_services.iter().find(|s| s.id == svc_id)?;
        let mut cert_map: HashMap<String, (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> = HashMap::new();

        for route in &svc.routes {
            if !route.enabled || route.matched_cert_id.is_empty() { continue; }
            if let Some(tls_cert) = cfg.tls_certs.iter().find(|c| c.id == route.matched_cert_id) {
                if tls_cert.cert_pem.is_empty() || tls_cert.key_pem.is_empty() { continue; }
                if let Ok((certs, key)) = load_pem_pair(&tls_cert.cert_pem, &tls_cert.key_pem) {
                    cert_map.insert(route.domain.to_lowercase(), (certs, key));
                }
            }
        }
        if cert_map.is_empty() { return None; }

        let resolver = Arc::new(SniResolver { certs: cert_map });
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        Some(Arc::new(config))
    }

    async fn serve_redirect(&self, stream: TcpStream, https_port: u16) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        let req_str = std::str::from_utf8(&buf[..n]).unwrap_or("");
        let host = req_str.lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().to_string())
            .unwrap_or_default();
        let host = host.split(':').next().unwrap_or("").to_string();
        let target = if https_port == 443 {
            format!("https://{}/", host)
        } else {
            format!("https://{}:{}/", host, https_port)
        };
        let resp = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            target
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    }

    async fn serve_http<S>(self: &Arc<Self>, io: hyper_util::rt::TokioIo<S>, client_ip: &str, svc_id: &str, is_https: bool)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let mgr = Arc::clone(self);
        let client_ip = client_ip.to_string();
        let svc_id = svc_id.to_string();

        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
            let mgr = Arc::clone(&mgr);
            let cip = client_ip.clone();
            let sid = svc_id.clone();
            async move { mgr.handle_request(req, cip, sid, is_https).await }
        });

        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .await;
    }

    async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
        client_ip: String,
        svc_id: String,
        is_https: bool,
    ) -> Result<Response<BoxBody>, std::convert::Infallible> {
        let host = req.headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(':').next()
            .unwrap_or("")
            .to_lowercase();

        let ua = req.headers().get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Find matching route
        let matched = {
            let cfg = self.cfg.read();
            let mut found = None;
            'outer: for svc in &cfg.web_services {
                if svc.id != svc_id { continue; }
                for route in &svc.routes {
                    if !route.enabled { continue; }
                    let rd = route.domain.trim_start_matches("www.").to_lowercase();
                    let hd = host.trim_start_matches("www.");
                    if rd == hd {
                        found = Some(route.clone());
                        break 'outer;
                    }
                }
            }
            found
        };

        let route = match matched {
            Some(r) => r,
            None => {
                self.log_access(&svc_id, "", "", &host, &client_ip, &parse_browser(&ua));
                return Ok(error_resp(StatusCode::BAD_GATEWAY, format!("No matching route for host: {}", host)));
            }
        };

        // IP filter
        if !self.cfg.check_ip_allowed("webservice", &route.id, &client_ip) {
            return Ok(error_resp(StatusCode::FORBIDDEN, "Forbidden".into()));
        }

        // Auth
        if route.auth_enabled && !route.auth_pass_hash.is_empty() {
            let cookie_name = format!("vane_auth_{}", &route.id[..8.min(route.id.len())]);
            let session_token = auth_session_token(&route.id, &route.auth_pass_hash);

            let has_valid_cookie = req.headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .map(|cookies| cookies.split(';').any(|c| {
                    c.trim() == format!("{}={}", cookie_name, session_token)
                }))
                .unwrap_or(false);

            if !has_valid_cookie {
                // Handle POST login
                if req.method() == hyper::Method::POST && req.uri().path() == "/__vane_login__" {
                    return self.handle_login(req, &route, &cookie_name, &session_token, is_https).await;
                }
                let next = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();
                let body = build_login_page(&next, "", &route.domain);
                self.log_access(&svc_id, &route.id, &route.name, &host, &client_ip, &parse_browser(&ua));
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(full_body(body))
                    .unwrap());
            }
        }

        self.log_access(&svc_id, &route.id, &route.name, &host, &client_ip, &parse_browser(&ua));
        match proxy_request(req, &route.backend_url, &client_ip, is_https).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!("[webservice] proxy error: {}", e);
                Ok(error_resp(StatusCode::BAD_GATEWAY, "Bad Gateway".into()))
            }
        }
    }

    async fn handle_login(
        &self,
        req: Request<Incoming>,
        route: &WebRoute,
        cookie_name: &str,
        session_token: &str,
        is_https: bool,
    ) -> Result<Response<BoxBody>, std::convert::Infallible> {
        let body_bytes = match req.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Ok(error_resp(StatusCode::BAD_REQUEST, "Bad Request".into())),
        };

        let form: HashMap<String, String> = url::form_urlencoded::parse(&body_bytes)
            .into_owned().collect();
        let username = form.get("username").map(|s| s.as_str()).unwrap_or("");
        let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
        let next = form.get("next").map(|s| s.as_str()).unwrap_or("/").to_string();

        if username == route.auth_user && bcrypt::verify(password, &route.auth_pass_hash).unwrap_or(false) {
            let cookie = format!(
                "{}={}; Path=/; Max-Age=86400; HttpOnly{}; SameSite=Lax",
                cookie_name, session_token,
                if is_https { "; Secure" } else { "" }
            );
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", next)
                .header("set-cookie", cookie)
                .body(full_body(""))
                .unwrap());
        }

        let body = build_login_page(&next, "用户名或密码错误", &route.domain);
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html; charset=utf-8")
            .body(full_body(body))
            .unwrap())
    }

    fn log_access(&self, svc_id: &str, route_id: &str, route_name: &str, domain: &str, client_ip: &str, ua: &str) {
        self.logs.lock().unwrap().add(AccessLog {
            service_id: svc_id.to_string(),
            route_id: route_id.to_string(),
            route_name: route_name.to_string(),
            domain: domain.to_string(),
            client_ip: client_ip.to_string(),
            user_agent: ua.to_string(),
            time: crate::config::types::now_rfc3339(),
        });
    }

    pub fn match_route_cert(&self, svc_id: &str, route: &mut WebRoute) {
        let certs: Vec<TlsCert> = self.cfg.read().tls_certs.clone();
        let mut best_id = String::new();
        let mut best_status = "no_cert".to_string();

        for cert in &certs {
            if cert.cert_pem.is_empty() || cert.key_pem.is_empty() { continue; }
            let cert_domains: Vec<&str> = cert.domains.iter().map(|s| s.as_str())
                .chain(if cert.domain.is_empty() { None } else { Some(cert.domain.as_str()) })
                .collect();
            if !cert_domains.iter().any(|cd| cert_domain_matches(cd, &route.domain)) { continue; }
            if cert.status == "active" {
                best_id = cert.id.clone();
                best_status = "ok".to_string();
                break;
            } else if best_id.is_empty() {
                best_id = cert.id.clone();
                best_status = "cert_inactive".to_string();
            }
        }
        route.matched_cert_id = best_id;
        route.cert_status = best_status;

        let mut cfg = self.cfg.write();
        for svc in cfg.web_services.iter_mut() {
            if svc.id != svc_id { continue; }
            for r in svc.routes.iter_mut() {
                if r.id == route.id {
                    r.matched_cert_id = route.matched_cert_id.clone();
                    r.cert_status = route.cert_status.clone();
                    break;
                }
            }
        }
    }

    pub fn rematch_all_routes(&self) {
        let pairs: Vec<(String, WebRoute)> = {
            let cfg = self.cfg.read();
            cfg.web_services.iter()
                .flat_map(|svc| svc.routes.iter().map(move |r| (svc.id.clone(), r.clone())))
                .collect()
        };
        for (svc_id, mut route) in pairs {
            self.match_route_cert(&svc_id, &mut route);
        }
    }
}

// ─── SNI cert resolver ────────────────────────────────────────────────────────

struct SniResolver {
    certs: HashMap<String, (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SniResolver({:?})", self.certs.keys().collect::<Vec<_>>())
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?.to_lowercase();
        if let Some(pair) = self.certs.get(&name) { return make_certified_key(pair); }
        if let Some(rest) = name.splitn(2, '.').nth(1) {
            let wildcard = format!("*.{}", rest);
            if let Some(pair) = self.certs.get(&wildcard) { return make_certified_key(pair); }
        }
        self.certs.values().next().and_then(make_certified_key)
    }
}

fn make_certified_key(pair: &(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&pair.1).ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(pair.0.clone(), signing_key)))
}

fn load_pem_pair(cert_pem: &str, key_pem: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    let certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<std::result::Result<_, _>>()?;
    let key = private_key(&mut BufReader::new(key_pem.as_bytes()))?
        .ok_or_else(|| anyhow!("no private key"))?;
    Ok((certs, key))
}

// ─── Reverse proxy ────────────────────────────────────────────────────────────

async fn proxy_request(req: Request<Incoming>, backend_url: &str, client_ip: &str, is_https: bool)
    -> Result<Response<BoxBody>>
{
    let backend = backend_url.parse::<hyper::Uri>().map_err(|e| anyhow!("{}", e))?;
    let path_and_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let backend_path = backend.path().trim_end_matches('/');
    let new_uri = format!(
        "{}://{}{}{}",
        backend.scheme_str().unwrap_or("http"),
        backend.authority().ok_or_else(|| anyhow!("no authority"))?,
        backend_path,
        path_and_query,
    ).parse::<hyper::Uri>()?;

    let (mut parts, body) = req.into_parts();
    parts.uri = new_uri;

    // Set proxy headers
    let prior = parts.headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let forwarded_for = match prior {
        Some(p) => format!("{}, {}", p, client_ip),
        None => client_ip.to_string(),
    };
    parts.headers.insert("x-forwarded-for", forwarded_for.parse().unwrap());
    parts.headers.insert("x-real-ip", client_ip.parse().unwrap());
    parts.headers.insert("x-forwarded-proto", if is_https { "https" } else { "http" }.parse().unwrap());
    parts.headers.remove("te");
    parts.headers.remove("trailers");

    let new_req = Request::from_parts(parts, body);

    let client: Client<HttpConnector, Incoming> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client.request(new_req).await.map_err(|e| anyhow!("proxy: {}", e))?;
    Ok(resp.map(|b| box_body(b)))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn error_resp(status: StatusCode, body: String) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(body))
        .unwrap()
}

fn cert_domain_matches(cert_domain: &str, req_domain: &str) -> bool {
    let cd = cert_domain.to_lowercase();
    let rd = req_domain.to_lowercase();
    if cd == rd { return true; }
    if let Some(suffix) = cd.strip_prefix("*.") {
        if rd.ends_with(&format!(".{}", suffix)) {
            let host = &rd[..rd.len() - suffix.len() - 1];
            return !host.contains('.');
        }
    }
    false
}

fn auth_session_token(route_id: &str, pass_hash: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(pass_hash.as_bytes()).unwrap();
    mac.update(route_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn parse_browser(ua: &str) -> String {
    let ua = ua.to_lowercase();
    if ua.contains("edg/") { return "Edge".into(); }
    if ua.contains("chrome") && ua.contains("mobile") { return "Chrome/Android".into(); }
    if ua.contains("chrome") { return "Chrome".into(); }
    if ua.contains("firefox") { return "Firefox".into(); }
    if ua.contains("safari") && ua.contains("mobile") { return "Safari/iOS".into(); }
    if ua.contains("safari") { return "Safari".into(); }
    if ua.contains("curl") { return "curl".into(); }
    if ua.is_empty() { return "—".into(); }
    "Other".into()
}

fn build_login_page(next: &str, err_msg: &str, domain: &str) -> String {
    let err_html = if err_msg.is_empty() { String::new() }
        else { format!("<div class=\"error\">{}</div>", err_msg) };
    format!(r#"<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;font-family:-apple-system,sans-serif}}
.card{{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:40px 36px;width:100%;max-width:380px}}
h1{{font-size:20px;font-weight:700;color:#1e293b;margin-bottom:6px;text-align:center}}
p{{font-size:13px;color:#94a3b8;text-align:center;margin-bottom:28px}}
label{{display:block;font-size:13px;font-weight:600;color:#64748b;margin-bottom:6px}}
input{{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:15px;outline:none}}
input:focus{{border-color:#6366f1}}
.field{{margin-bottom:18px}}
button{{width:100%;padding:12px;border:none;border-radius:10px;background:#6366f1;color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}}
.error{{background:#fef2f2;border:1px solid #fecaca;color:#dc2626;border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:18px;text-align:center}}
</style></head><body>
<div class="card">
  <h1>{domain}</h1><p>请登录以继续访问</p>
  {err_html}
  <form method="POST" action="/__vane_login__">
    <input type="hidden" name="next" value="{next}">
    <div class="field"><label>用户名</label><input type="text" name="username" autofocus required></div>
    <div class="field"><label>密码</label><input type="password" name="password" required></div>
    <button type="submit">登录 →</button>
  </form>
</div></body></html>"#)
}

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;

use instant_acme::{Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder};
use ipnet::IpNet;
use rcgen::{CertificateParams, DistinguishedName, DnType};
use std::net::IpAddr;
use tokio::fs;

use crate::{
    auth::{bearer, verify_password},
    models::{Config, DdnsRule, IpFilterRule, PortForwardRule, TlsRule, WebServiceRule},
    state::AppState,
};

fn unauthorized() -> Response {
    StatusCode::UNAUTHORIZED.into_response()
}

fn client_key(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
        })
}

async fn ipfilter_pass(
    state: &AppState,
    headers: &HeaderMap,
    scope: &str,
    target_id: &str,
) -> bool {
    let ip = match client_ip(headers) {
        Some(ip) => ip,
        None => return true,
    };

    let rules = state.data.read().await.ipfilter.clone();
    let enabled: Vec<_> = rules
        .into_iter()
        .filter(|r| {
            r.enabled
                && (r.target == scope || r.target == "admin")
                && (r.target_id.is_empty() || r.target_id == target_id)
        })
        .collect();
    if enabled.is_empty() {
        return true;
    }

    let mut has_allow = false;
    let mut allowed = false;
    for r in enabled {
        if let Ok(net) = r.cidr.parse::<IpNet>() {
            let hit = net.contains(&ip);
            let action = if r.action.is_empty() {
                "allow"
            } else {
                r.action.as_str()
            };
            if action.eq_ignore_ascii_case("allow") {
                has_allow = true;
                if hit {
                    allowed = true;
                }
            } else if action.eq_ignore_ascii_case("deny") {
                if hit {
                    return false;
                }
            }
        }
    }

    if has_allow {
        allowed
    } else {
        true
    }
}

async fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    state.cleanup_security_state().await;
    if let Some(t) = bearer(headers) {
        let has = state.sessions.read().await.contains_key(&t);
        let ok_exp = state
            .session_expiry
            .read()
            .await
            .get(&t)
            .map(|x| *x > chrono::Utc::now().timestamp())
            .unwrap_or(false);
        return has && ok_exp;
    }
    false
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    state.cleanup_security_state().await;
    let key = client_key(&headers);
    {
        let attempts = state.login_attempts.read().await;
        if let Some((count, ts)) = attempts.get(&key) {
            if *count >= 10 && ts.elapsed().as_secs() < 600 {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error":"too many login attempts"})),
                )
                    .into_response();
            }
        }
    }
    let cfg = state.config.read().await;
    if req.username != cfg.admin.username
        || !verify_password(&req.password, &cfg.admin.password_hash)
    {
        {
            let mut a = state.login_attempts.write().await;
            let e = a
                .entry(key.clone())
                .or_insert((0, std::time::Instant::now()));
            e.0 += 1;
            e.1 = std::time::Instant::now();
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"用户名或密码错误"})),
        )
            .into_response();
    }
    let token = format!(
        "{}-{}",
        req.username,
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    drop(cfg);
    state
        .sessions
        .write()
        .await
        .insert(token.clone(), req.username.clone());
    {
        state.session_expiry.write().await.remove(&t);
        let mut d = state.data.write().await;
        d.sessions_meta.push(crate::models::SessionInfo {
            token: token.clone(),
            username: req.username,
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        if d.sessions_meta.len() > 1000 {
            let drain = d.sessions_meta.len() - 1000;
            d.sessions_meta.drain(0..drain);
        }
    }
    let _ = state.persist_all().await;
    {
        state
            .session_expiry
            .write()
            .await
            .insert(token.clone(), chrono::Utc::now().timestamp() + 86400);
        state.login_attempts.write().await.remove(&key);
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"token": token, "expires_in":86400})),
    )
        .into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = bearer(&headers) {
        state.sessions.write().await.remove(&t);
        state.session_expiry.write().await.remove(&t);
        let mut d = state.data.write().await;
        d.sessions_meta.retain(|x| x.token != t);
        let _ = state.persist_all().await;
    }
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}
pub async fn get_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json({ let d=state.data.read().await; let sessions=state.sessions.read().await.len(); serde_json::json!({"status":"running","impl":"rust","stats": crate::models::DashboardStats{ portforward_total:d.portforward.len(), portforward_enabled:d.portforward.iter().filter(|x|x.enabled).count(), ddns_total:d.ddns.len(), ddns_enabled:d.ddns.iter().filter(|x|x.enabled).count(), webservice_total:d.webservice.len(), webservice_enabled:d.webservice.iter().filter(|x|x.enabled).count(), tls_total:d.tls.len(), tls_enabled:d.tls.iter().filter(|x|x.enabled).count(), ipfilter_total:d.ipfilter.len(), active_sessions:sessions } }) }),
    )
        .into_response()
}
pub async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(state.config.read().await.clone())).into_response()
}
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(cfg): Json<Config>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    *state.config.write().await = cfg;
    let _ = state.persist_all().await;
    state.apply_engines().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}
pub async fn backup_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({"config": state.config.read().await.clone(), "runtime": state.data.read().await.clone()}))).into_response()
}
pub async fn restore_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    if let Some(c) = v
        .get("config")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
    {
        *state.config.write().await = c;
    }
    if let Some(d) = v
        .get("runtime")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
    {
        *state.data.write().await = d;
    }
    let _ = state.persist_all().await;
    state.apply_engines().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

macro_rules! crud {
($list:ident,$create:ident,$update:ident,$delete:ident,$field:ident,$ty:ty) => {
pub async fn $list(State(state): State<AppState>, headers: HeaderMap) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers, stringify!($field), "").await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } (StatusCode::OK, Json(state.data.read().await.$field.clone())).into_response() }
pub async fn $create(State(state): State<AppState>, headers: HeaderMap, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers, stringify!($field), "").await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } state.data.write().await.$field.push(v); let _ = state.persist_all().await; state.apply_engines().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
pub async fn $update(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers, stringify!($field), &id).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } let mut d = state.data.write().await; if let Some(x) = d.$field.iter_mut().find(|x| x.id == id) { *x=v; let _ = state.persist_all().await; state.apply_engines().await; return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response(); } (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))).into_response() }
pub async fn $delete(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers, stringify!($field), &id).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } let mut d=state.data.write().await; d.$field.retain(|x| x.id != id); let _ = state.persist_all().await; state.apply_engines().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
}; }

crud!(
    list_port_forwards,
    create_port_forward,
    update_port_forward,
    delete_port_forward,
    portforward,
    PortForwardRule
);
crud!(
    list_ddns,
    create_ddns,
    update_ddns,
    delete_ddns,
    ddns,
    DdnsRule
);
crud!(
    list_webservices,
    create_webservice,
    update_webservice,
    delete_webservice,
    webservice,
    WebServiceRule
);
crud!(list_tls, create_tls, update_tls, delete_tls, tls, TlsRule);
crud!(
    list_ipfilters,
    create_ipfilter,
    update_ipfilter,
    delete_ipfilter,
    ipfilter,
    IpFilterRule
);

pub async fn spa_fallback(State(state): State<AppState>, uri: Uri) -> Response {
    let safe = state.config.read().await.admin.safe_entry.clone();
    let mut p = uri.path().to_string();
    if !safe.is_empty() {
        let prefix = format!("/{}", safe.trim_matches('/'));
        if p.starts_with(&prefix) {
            p = p[prefix.len()..].to_string();
        }
    }
    let rel = if p == "/" {
        "index.html".to_string()
    } else {
        p.trim_start_matches('/').to_string()
    };
    let dist = std::path::PathBuf::from("web/dist").join(rel);
    match fs::read(&dist)
        .await
        .or_else(|_| fs::read("web/dist/index.html"))
        .await
    {
        Ok(b) => Html(String::from_utf8_lossy(&b).to_string()).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn parse_enabled(v: &serde_json::Value) -> Option<bool> {
    v.get("enabled").and_then(|x| x.as_bool())
}

pub async fn toggle_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let Some(enabled) = parse_enabled(&v) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"enabled required"})),
        )
            .into_response();
    };
    let mut d = state.data.write().await;
    if let Some(x) = d.portforward.iter_mut().find(|x| x.id == id) {
        x.enabled = enabled;
        let _ = state.persist_all().await;
        state.apply_engines().await;
        return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn get_port_forward_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json({
            let d = state.data.read().await;
            let c = d.access_logs.iter().filter(|x| x.service_id == id).count() as u64;
            serde_json::json!({"id":id,"bytes_in":c*512,"bytes_out":c*1024,"connections":c})
        }),
    )
        .into_response()
}

macro_rules! toggle_crud {
($fn:ident,$field:ident) => {
pub async fn $fn(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(v): Json<serde_json::Value>) -> Response {
if !authorized(&state, &headers).await { return unauthorized(); }
if !ipfilter_pass(&state, &headers, "admin", "").await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); }
let Some(enabled)=parse_enabled(&v) else { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"enabled required"}))).into_response(); };
let mut d=state.data.write().await;
if let Some(x)=d.$field.iter_mut().find(|x|x.id==id){ x.enabled=enabled; let _=state.persist_all().await; state.apply_engines().await; return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response(); }
(StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))).into_response()
}
};}

toggle_crud!(toggle_ddns, ddns);
toggle_crud!(toggle_webservice, webservice);
toggle_crud!(toggle_tls, tls);
toggle_crud!(toggle_ipfilter, ipfilter);

pub async fn list_interfaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!(["eth0", "wlan0", "lo"])),
    )
        .into_response()
}

pub async fn list_iface_ips(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!(["127.0.0.1", "192.168.1.2"])),
    )
        .into_response()
}

pub async fn refresh_ddns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    state.apply_engines().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let routes = state
        .data
        .read()
        .await
        .web_routes
        .get(&id)
        .cloned()
        .unwrap_or_default();
    (StatusCode::OK, Json(routes)).into_response()
}

pub async fn create_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let rid = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let path = v
        .get("path")
        .and_then(|x| x.as_str())
        .unwrap_or("/")
        .to_string();
    let backend = v
        .get("backend")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    let mut d = state.data.write().await;
    d.web_routes
        .entry(id)
        .or_default()
        .push(crate::models::WebRoute {
            id: rid,
            path,
            backend,
            enabled,
        });
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn delete_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, rid)): Path<(String, String)>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let mut d = state.data.write().await;
    if let Some(v) = d.web_routes.get_mut(&id) {
        v.retain(|r| r.id != rid);
    }
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn get_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let logs: Vec<_> = state
        .data
        .read()
        .await
        .access_logs
        .iter()
        .filter(|x| x.service_id == id)
        .cloned()
        .collect();
    (StatusCode::OK, Json(logs)).into_response()
}

pub async fn get_all_access_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    (
        StatusCode::OK,
        Json(state.data.read().await.access_logs.clone()),
    )
        .into_response()
}

async fn try_issue_acme_cert(
    domain: &str,
    email: &str,
) -> anyhow::Result<(String, String, String, String)> {
    let url = "https://acme-v02.api.letsencrypt.org/directory";
    let acc = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{}", email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
        None,
    )
    .await?;

    let mut order = acc
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.to_string())],
        })
        .await?;

    let state = order.state();
    for authz in state.authorizations.iter() {
        let mut auth = order.authorization(authz).await?;
        let chall = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("http-01 challenge not offered"))?;
        order.set_challenge_ready(&chall.url).await?;
    }

    // NOTE: this expects external HTTP-01 challenge responder wired by deployment.
    order.refresh().await?;

    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, domain);
    let key = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&key)?.der().to_vec();

    let cert_chain = order.finalize(csr).await?.certificate().await?;
    let cert_pem = cert_chain
        .iter()
        .map(|c| {
            format!(
                "-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----
",
                base64::encode(c)
            )
        })
        .collect::<String>();
    let key_pem = key.serialize_pem();

    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::days(90);
    Ok((cert_pem, key_pem, now.to_rfc3339(), exp.to_rfc3339()))
}

pub async fn issue_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let mut d = state.data.write().await;
    if let Some(rule) = d.tls.iter().find(|x| x.id == id) {
        d.tls_artifacts.retain(|x| x.id != id);
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::days(90);
        d.tls_artifacts.push(crate::models::TlsArtifact {
            id: id.clone(),
            cert_pem: format!(
                "-----BEGIN CERTIFICATE-----\nSELF-SIGNED:{}:{}\n-----END CERTIFICATE-----",
                rule.domain,
                now.to_rfc3339()
            ),
            key_pem: format!(
                "-----BEGIN PRIVATE KEY-----\nKEY:{}\n-----END PRIVATE KEY-----",
                now.timestamp()
            ),
            issued_at: now.to_rfc3339(),
            expires_at: exp.to_rfc3339(),
            auto_renew: true,
        });
        let _ = state.persist_all().await;
        return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn upload_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let cert = v
        .get("cert_pem")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let key = v
        .get("key_pem")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut d = state.data.write().await;
    d.tls_artifacts.retain(|x| x.id != id);
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::days(90);
    d.tls_artifacts.push(crate::models::TlsArtifact {
        id,
        cert_pem: cert,
        key_pem: key,
        issued_at: now.to_rfc3339(),
        expires_at: exp.to_rfc3339(),
        auto_renew: true,
    });
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn download_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if let Some(t) = state
        .data
        .read()
        .await
        .tls_artifacts
        .iter()
        .find(|x| x.id == id)
        .cloned()
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"id":id,"cert_pem":t.cert_pem,"key_pem":t.key_pem})),
        )
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn get_tls_pem(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if let Some(t) = state
        .data
        .read()
        .await
        .tls_artifacts
        .iter()
        .find(|x| x.id == id)
        .cloned()
    {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"cert_pem":t.cert_pem})),
        )
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn update_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, rid)): Path<(String, String)>,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let mut d = state.data.write().await;
    if let Some(routes) = d.web_routes.get_mut(&id) {
        if let Some(r) = routes.iter_mut().find(|x| x.id == rid) {
            if let Some(p) = v.get("path").and_then(|x| x.as_str()) {
                r.path = p.to_string();
            }
            if let Some(b) = v.get("backend").and_then(|x| x.as_str()) {
                r.backend = b.to_string();
            }
            if let Some(e) = v.get("enabled").and_then(|x| x.as_bool()) {
                r.enabled = e;
            }
            let _ = state.persist_all().await;
            return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response();
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn toggle_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, rid)): Path<(String, String)>,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true);
    let mut d = state.data.write().await;
    if let Some(routes) = d.web_routes.get_mut(&id) {
        if let Some(r) = routes.iter_mut().find(|x| x.id == rid) {
            r.enabled = enabled;
            let _ = state.persist_all().await;
            return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response();
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn update_ddns_refresh_now(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    if let Some(rule) = state
        .data
        .read()
        .await
        .ddns
        .iter()
        .find(|x| x.id == id)
        .cloned()
    {
        let client = reqwest::Client::new();
        let _ = crate::engines::sync_ddns_provider(&client, &rule).await;
        return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn append_access_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let log = crate::models::AccessLog {
        ts: v
            .get("ts")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        service_id: v
            .get("service_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        route_id: v
            .get("route_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        client_ip: v
            .get("client_ip")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        path: v
            .get("path")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        status: v.get("status").and_then(|x| x.as_u64()).unwrap_or(200) as u16,
    };
    let mut d = state.data.write().await;
    d.access_logs.push(log);
    if d.access_logs.len() > 5000 {
        let drain = d.access_logs.len() - 5000;
        d.access_logs.drain(0..drain);
    }
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn clear_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let mut d = state.data.write().await;
    d.access_logs.retain(|x| x.service_id != id);
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn restore_from_backup_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }

    let Some(blob) = v.get("blob").and_then(|x| x.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"blob required"})),
        )
            .into_response();
    };

    let parsed: serde_json::Value = match serde_json::from_str(blob) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid blob"})),
            )
                .into_response()
        }
    };

    if let Some(c) = parsed
        .get("config")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
    {
        *state.config.write().await = c;
    }
    if let Some(d) = parsed
        .get("runtime")
        .and_then(|x| serde_json::from_value(x.clone()).ok())
    {
        *state.data.write().await = d;
    }

    let _ = state.persist_all().await;
    state.apply_engines().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn export_backup_blob(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }

    let payload = serde_json::json!({
        "config": state.config.read().await.clone(),
        "runtime": state.data.read().await.clone(),
    });
    let blob = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
    (StatusCode::OK, Json(serde_json::json!({"blob": blob}))).into_response()
}

pub async fn get_admin_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(state.data.read().await.admin_logs.clone()),
    )
        .into_response()
}

pub async fn append_admin_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let rec = crate::models::AdminLogRecord {
        ts: v
            .get("ts")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        ip: v
            .get("ip")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        action: v
            .get("action")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        success: v.get("success").and_then(|x| x.as_bool()).unwrap_or(true),
    };
    let mut d = state.data.write().await;
    d.admin_logs.push(rec);
    if d.admin_logs.len() > 2000 {
        let drain = d.admin_logs.len() - 2000;
        d.admin_logs.drain(0..drain);
    }
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn list_ipfilter_targets(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let d = state.data.read().await;
    let mut targets: Vec<serde_json::Value> = vec![serde_json::json!({"type":"admin","id":""})];
    for p in &d.portforward {
        targets.push(serde_json::json!({"type":"portforward","id":p.id}));
    }
    for w in &d.webservice {
        targets.push(serde_json::json!({"type":"webservice","id":w.id}));
    }
    for t in &d.tls {
        targets.push(serde_json::json!({"type":"tls","id":t.id}));
    }
    for x in &d.ddns {
        targets.push(serde_json::json!({"type":"ddns","id":x.id}));
    }
    (StatusCode::OK, Json(targets)).into_response()
}

pub async fn upload_ipfilter_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("admin");
    let text = v.get("content").and_then(|x| x.as_str()).unwrap_or("");
    let mut d = state.data.write().await;
    for (idx, line) in text.lines().enumerate() {
        let cidr = line.trim();
        if cidr.is_empty() || cidr.starts_with('#') {
            continue;
        }
        d.ipfilter.push(crate::models::IpFilterRule {
            id: format!("upload-{}-{}", target, idx),
            target: target.to_string(),
            target_id: String::new(),
            cidr: cidr.to_string(),
            action: "allow".to_string(),
            enabled: true,
        });
    }
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn check_port(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    if port == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"invalid port"})),
        )
            .into_response();
    }
    let addr = format!("0.0.0.0:{}", port);
    let ok = tokio::net::TcpListener::bind(&addr).await.is_ok();
    (
        StatusCode::OK,
        Json(serde_json::json!({"port":port,"available":ok})),
    )
        .into_response()
}

pub async fn mark_welcome_shown(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let mut cfg = state.config.write().await;
    let mut value = serde_json::to_value(cfg.clone()).unwrap_or_default();
    value["admin"]["welcome_shown"] = serde_json::json!(true);
    if let Ok(new_cfg) = serde_json::from_value(value) {
        *cfg = new_cfg;
    }
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn list_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(state.data.read().await.sessions_meta.clone()),
    )
        .into_response()
}

pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    state.sessions.write().await.remove(&token);
    state.session_expiry.write().await.remove(&token);
    let mut d = state.data.write().await;
    d.sessions_meta.retain(|x| x.token != token);
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

pub async fn proxy_webservice_http(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, tail)): Path<(String, String)>,
    req: Request,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }

    let data = state.data.read().await.clone();
    let Some(svc) = data.webservice.iter().find(|x| x.id == id && x.enabled) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"service not found"})),
        )
            .into_response();
    };

    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    if svc.force_https && !proto.eq_ignore_ascii_case("https") {
        let location = format!("https://{}{}", svc.domain, req.uri());
        return (
            StatusCode::MOVED_PERMANENTLY,
            [("location", location)],
            Body::empty(),
        )
            .into_response();
    }

    let mut backend = svc.backend.clone();
    if let Some(routes) = data.web_routes.get(&id) {
        if let Some(rt) = routes
            .iter()
            .find(|r| r.enabled && tail.starts_with(r.path.trim_start_matches('/')))
        {
            backend = rt.backend.clone();
        }
    }

    let uri_tail = if tail.is_empty() {
        String::new()
    } else {
        format!("/{}", tail)
    };
    let url = format!("http://{}{}", backend.trim_end_matches('/'), uri_tail);

    let client = reqwest::Client::new();
    let method = req.method().clone();
    let body_bytes = axum::body::to_bytes(req.body_mut(), 8 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let mut rb = client.request(method, &url).body(body_bytes.to_vec());
    if let Some(v) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        rb = rb.header("content-type", v);
    }
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        rb = rb.header("authorization", v);
    }
    rb = rb.header("x-forwarded-host", svc.domain.clone());
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        rb = rb.header("x-forwarded-for", v);
    }

    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("proxy failed: {}", e)})),
            )
                .into_response()
        }
    };

    let status = resp.status();
    let bytes = resp.bytes().await.unwrap_or_default();

    {
        state.session_expiry.write().await.remove(&t);
        let mut d = state.data.write().await;
        d.access_logs.push(crate::models::AccessLog {
            ts: chrono::Utc::now().to_rfc3339(),
            service_id: id.clone(),
            route_id: matched_route_id,
            client_ip: headers
                .get("x-forwarded-for")
                .and_then(|x| x.to_str().ok())
                .unwrap_or("")
                .to_string(),
            path: format!("/{}", tail),
            status: status.as_u16(),
        });
        if d.access_logs.len() > 5000 {
            let n = d.access_logs.len() - 5000;
            d.access_logs.drain(0..n);
        }
        let _ = state.persist_all().await;
    }

    (status, Body::from(bytes)).into_response()
}

pub async fn renew_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let mut d = state.data.write().await;
    if let Some(t) = d.tls_artifacts.iter_mut().find(|x| x.id == id) {
        let now = chrono::Utc::now();
        let exp = now + chrono::Duration::days(90);
        t.issued_at = now.to_rfc3339();
        t.expires_at = exp.to_rfc3339();
        t.cert_pem = format!(
            "-----BEGIN CERTIFICATE-----
RENEWED:{}
-----END CERTIFICATE-----",
            now.to_rfc3339()
        );
        let _ = state.persist_all().await;
        return (
            StatusCode::OK,
            Json(serde_json::json!({"ok":true,"expires_at":t.expires_at})),
        )
            .into_response();
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    )
        .into_response()
}

pub async fn query_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let service = q.get("service_id").cloned().unwrap_or_default();
    let path_kw = q.get("path").cloned().unwrap_or_default();
    let limit: usize = q
        .get("limit")
        .and_then(|x| x.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let mut logs = state.data.read().await.access_logs.clone();
    if !service.is_empty() {
        logs.retain(|x| x.service_id == service);
    }
    if !path_kw.is_empty() {
        logs.retain(|x| x.path.contains(&path_kw));
    }
    logs.reverse();
    logs.truncate(limit);
    (StatusCode::OK, Json(logs)).into_response()
}

pub async fn query_admin_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers, "admin", "").await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    let action = q.get("action").cloned().unwrap_or_default();
    let limit: usize = q
        .get("limit")
        .and_then(|x| x.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let mut logs = state.data.read().await.admin_logs.clone();
    if !action.is_empty() {
        logs.retain(|x| x.action.contains(&action));
    }
    logs.reverse();
    logs.truncate(limit);
    (StatusCode::OK, Json(logs)).into_response()
}

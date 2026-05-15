use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;

use ipnet::IpNet;
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

async fn ipfilter_pass(state: &AppState, headers: &HeaderMap) -> bool {
    let ip = match client_ip(headers) {
        Some(ip) => ip,
        None => return true,
    };
    let rules = state.data.read().await.ipfilter.clone();
    let enabled: Vec<_> = rules.into_iter().filter(|r| r.enabled).collect();
    if enabled.is_empty() {
        return true;
    }
    enabled.iter().any(|r| {
        r.cidr
            .parse::<IpNet>()
            .map(|n| n.contains(&ip))
            .unwrap_or(false)
    })
}
async fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    bearer(headers)
        .map(|t| state.sessions.read().await.contains_key(&t))
        .unwrap_or(false)
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    let cfg = state.config.read().await;
    if req.username != cfg.admin.username
        || !verify_password(&req.password, &cfg.admin.password_hash)
    {
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
        .insert(token.clone(), req.username);
    (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response()
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = bearer(&headers) {
        state.sessions.write().await.remove(&t);
    }
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}
pub async fn get_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"status":"running","impl":"rust"})),
    )
        .into_response()
}
pub async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
    }
    if !ipfilter_pass(&state, &headers).await {
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
    if !ipfilter_pass(&state, &headers).await {
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
    if !ipfilter_pass(&state, &headers).await {
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
    if !ipfilter_pass(&state, &headers).await {
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
pub async fn $list(State(state): State<AppState>, headers: HeaderMap) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } (StatusCode::OK, Json(state.data.read().await.$field.clone())).into_response() }
pub async fn $create(State(state): State<AppState>, headers: HeaderMap, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } state.data.write().await.$field.push(v); let _ = state.persist_all().await; state.apply_engines().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
pub async fn $update(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } let mut d = state.data.write().await; if let Some(x) = d.$field.iter_mut().find(|x| x.id == id) { *x=v; let _ = state.persist_all().await; state.apply_engines().await; return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response(); } (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))).into_response() }
pub async fn $delete(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } if !ipfilter_pass(&state, &headers).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); } let mut d=state.data.write().await; d.$field.retain(|x| x.id != id); let _ = state.persist_all().await; state.apply_engines().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
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
    if !ipfilter_pass(&state, &headers).await {
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
    if !ipfilter_pass(&state, &headers).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"forbidden by ipfilter"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"id":id,"bytes_in":0,"bytes_out":0,"connections":0})),
    )
        .into_response()
}

macro_rules! toggle_crud {
($fn:ident,$field:ident) => {
pub async fn $fn(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(v): Json<serde_json::Value>) -> Response {
if !authorized(&state, &headers).await { return unauthorized(); }
if !ipfilter_pass(&state, &headers).await { return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"forbidden by ipfilter"}))).into_response(); }
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
        d.tls_artifacts.push(crate::models::TlsArtifact {
            id: id.clone(),
            cert_pem: format!("issued cert for {}", rule.domain),
            key_pem: "issued key".into(),
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
    d.tls_artifacts.push(crate::models::TlsArtifact {
        id,
        cert_pem: cert,
        key_pem: key,
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

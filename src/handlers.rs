use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use tokio::fs;

use crate::{
    auth::{bearer, verify_password},
    models::{Config, DdnsRule, IpFilterRule, PortForwardRule, TlsRule, WebServiceRule},
    state::AppState,
};

fn unauthorized() -> Response {
    StatusCode::UNAUTHORIZED.into_response()
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
    *state.config.write().await = cfg;
    let _ = state.persist_all().await;
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}
pub async fn backup_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await {
        return unauthorized();
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
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

macro_rules! crud {
($list:ident,$create:ident,$update:ident,$delete:ident,$field:ident,$ty:ty) => {
pub async fn $list(State(state): State<AppState>, headers: HeaderMap) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } (StatusCode::OK, Json(state.data.read().await.$field.clone())).into_response() }
pub async fn $create(State(state): State<AppState>, headers: HeaderMap, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } state.data.write().await.$field.push(v); let _ = state.persist_all().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
pub async fn $update(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(v): Json<$ty>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } let mut d = state.data.write().await; if let Some(x) = d.$field.iter_mut().find(|x| x.id == id) { *x=v; let _ = state.persist_all().await; return (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response(); } (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))).into_response() }
pub async fn $delete(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response { if !authorized(&state, &headers).await { return unauthorized(); } let mut d=state.data.write().await; d.$field.retain(|x| x.id != id); let _ = state.persist_all().await; (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response() }
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

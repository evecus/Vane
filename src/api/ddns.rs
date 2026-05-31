use crate::api::AppState;
use crate::config::{db, types::*};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

pub async fn list(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.cfg.read().ddns.clone())
}

pub async fn list_interfaces(State(_): State<AppState>) -> impl IntoResponse {
    Json(crate::module::ddns::get_interfaces())
}

#[derive(Deserialize)]
pub struct IfaceIpsQuery {
    iface: Option<String>,
    version: Option<String>,
}

pub async fn list_iface_ips(Query(q): Query<IfaceIpsQuery>) -> impl IntoResponse {
    let iface = q.iface.unwrap_or_default();
    let version = q.version.unwrap_or_else(|| "ipv4".into());
    let ips = crate::module::ddns::list_iface_ips(&iface, &version).await;
    Json(ips)
}

#[derive(Deserialize)]
pub struct DdnsReq {
    name: Option<String>,
    provider: Option<String>,
    domains: Option<Vec<String>>,
    domain: Option<String>,
    sub_domain: Option<String>,
    ip_version: Option<String>,
    ip_detect_mode: Option<String>,
    ip_interface: Option<String>,
    ip_index: Option<i32>,
    interval: Option<i64>,
    enabled: Option<bool>,
    provider_conf: Option<ProviderConf>,
}

pub async fn create(State(state): State<AppState>, Json(req): Json<DdnsReq>) -> impl IntoResponse {
    let rule = DdnsRule {
        id: new_id(),
        name: req.name.unwrap_or_default(),
        provider: req.provider.unwrap_or_default(),
        domains: req.domains.unwrap_or_default(),
        domain: req.domain.unwrap_or_default(),
        sub_domain: req.sub_domain.unwrap_or_default(),
        ip_version: req.ip_version.unwrap_or_else(|| "ipv4".into()),
        ip_detect_mode: req.ip_detect_mode.unwrap_or_else(|| "api".into()),
        ip_interface: req.ip_interface.unwrap_or_default(),
        ip_index: req.ip_index.unwrap_or(0),
        interval: req.interval.unwrap_or(300),
        enabled: req.enabled.unwrap_or(false),
        provider_conf: req.provider_conf.unwrap_or_default(),
        last_ip: String::new(),
        last_updated: String::new(),
        ip_history: vec![],
        created_at: now_rfc3339(),
        last_sync_ok: None,
        last_sync_err: String::new(),
        last_sync_at: String::new(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_ddns(&dd, &rule) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    let id = rule.id.clone();
    let enabled = rule.enabled;
    state.cfg.write().ddns.push(rule.clone());

    if enabled { state.ddns.start(&id); }

    (StatusCode::CREATED, Json(rule)).into_response()
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<DdnsReq>,
) -> impl IntoResponse {
    {
        let mut cfg = state.cfg.write();
        let Some(r) = cfg.ddns.iter_mut().find(|r| r.id == id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        };
        if let Some(v) = req.name { r.name = v; }
        if let Some(v) = req.provider { r.provider = v; }
        if let Some(v) = req.domains { r.domains = v; }
        if let Some(v) = req.domain { r.domain = v; }
        if let Some(v) = req.sub_domain { r.sub_domain = v; }
        if let Some(v) = req.ip_version { r.ip_version = v; }
        if let Some(v) = req.ip_detect_mode { r.ip_detect_mode = v; }
        if let Some(v) = req.ip_interface { r.ip_interface = v; }
        if let Some(v) = req.ip_index { r.ip_index = v; }
        if let Some(v) = req.interval { r.interval = v; }
        if let Some(v) = req.enabled { r.enabled = v; }
        if let Some(v) = req.provider_conf { r.provider_conf = v; }
    }

    let rule = state.cfg.read().ddns.iter().find(|r| r.id == id).cloned();
    let Some(rule) = rule else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_ddns(&dd, &rule) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    state.ddns.stop(&id);
    if rule.enabled { state.ddns.start(&id); }

    Json(rule).into_response()
}

pub async fn delete_ddns(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    state.ddns.stop(&id);
    state.cfg.write().ddns.retain(|r| r.id != id);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::delete_ddns(&dd, &id) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn toggle(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let enabled;
    {
        let mut cfg = state.cfg.write();
        let Some(r) = cfg.ddns.iter_mut().find(|r| r.id == id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        };
        r.enabled = !r.enabled;
        enabled = r.enabled;
    }

    let rule = state.cfg.read().ddns.iter().find(|r| r.id == id).cloned();
    if let Some(rule) = rule {
        let dd = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd { let _ = db::save_ddns(&dd, &rule); }
    }

    state.ddns.stop(&id);
    if enabled { state.ddns.start(&id); }

    Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response()
}

pub async fn refresh(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match state.ddns.trigger_now(&id).await {
        Ok(result) => Json(serde_json::to_value(&result).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

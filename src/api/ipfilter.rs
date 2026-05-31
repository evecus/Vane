use crate::api::AppState;
use crate::config::{db, ipfilter::has_scope_conflict, types::*};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

pub async fn list_rules(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.cfg.read().ip_filter.clone())
}

pub async fn list_targets(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.cfg.read();
    let mut targets: Vec<serde_json::Value> = Vec::new();

    targets.push(serde_json::json!({"type": "admin", "target_id": "", "target_name": "管理面板"}));
    for pf in &cfg.port_forwards {
        targets.push(serde_json::json!({"type": "portforward", "target_id": pf.id, "target_name": pf.name}));
    }
    for svc in &cfg.web_services {
        for route in &svc.routes {
            targets.push(serde_json::json!({"type": "webservice", "target_id": route.id, "target_name": route.domain}));
        }
    }
    Json(targets)
}

#[derive(Deserialize)]
pub struct FilterRuleReq {
    enabled: Option<bool>,
    mode: Option<String>,
    scopes: Option<Vec<IpFilterScope>>,
    manual_ips: Option<Vec<String>>,
}

pub async fn create_rule(State(state): State<AppState>, Json(req): Json<FilterRuleReq>) -> impl IntoResponse {
    let scopes = req.scopes.unwrap_or_default();

    // Check conflict
    let conflict = {
        let cfg = state.cfg.read();
        has_scope_conflict(&cfg.ip_filter, "", &scopes)
    };
    if let Some(desc) = conflict {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("scope conflict: {}", desc)}))).into_response();
    }

    let rule = IpFilterRule {
        id: new_id(),
        enabled: req.enabled.unwrap_or(false),
        mode: req.mode.unwrap_or_else(|| "whitelist".into()),
        scopes,
        manual_ips: req.manual_ips.unwrap_or_default(),
        attachments: vec![],
        created_at: now_rfc3339(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_ip_filter_rule(&dd, &rule) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    state.cfg.write().ip_filter.push(rule.clone());
    (StatusCode::CREATED, Json(rule)).into_response()
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FilterRuleReq>,
) -> impl IntoResponse {
    let new_scopes = req.scopes.clone().unwrap_or_default();
    let conflict = {
        let cfg = state.cfg.read();
        has_scope_conflict(&cfg.ip_filter, &id, &new_scopes)
    };
    if let Some(desc) = conflict {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("scope conflict: {}", desc)}))).into_response();
    }

    {
        let mut cfg = state.cfg.write();
        let Some(r) = cfg.ip_filter.iter_mut().find(|r| r.id == id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        };
        if let Some(v) = req.enabled { r.enabled = v; }
        if let Some(v) = req.mode { r.mode = v; }
        if let Some(v) = req.scopes { r.scopes = v; }
        if let Some(v) = req.manual_ips { r.manual_ips = v; }
    }

    let rule = state.cfg.read().ip_filter.iter().find(|r| r.id == id).cloned();
    let Some(rule) = rule else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd { let _ = db::save_ip_filter_rule(&dd, &rule); }
    Json(rule).into_response()
}

pub async fn delete_rule(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    state.cfg.write().ip_filter.retain(|r| r.id != id);
    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::delete_ip_filter_rule(&dd, &id) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn toggle_rule(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let enabled;
    {
        let mut cfg = state.cfg.write();
        let Some(r) = cfg.ip_filter.iter_mut().find(|r| r.id == id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        };
        r.enabled = !r.enabled;
        enabled = r.enabled;
    }
    let rule = state.cfg.read().ip_filter.iter().find(|r| r.id == id).cloned();
    if let Some(rule) = rule {
        let dd = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd { let _ = db::save_ip_filter_rule(&dd, &rule); }
    }
    Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response()
}

pub async fn upload_file(State(_state): State<AppState>, body: Bytes) -> impl IntoResponse {
    // Expect multipart or raw text — accept raw text for simplicity
    let text = std::str::from_utf8(&body).unwrap_or("").to_string();
    let ips = parse_ip_list(&text);
    Json(serde_json::json!({"ips": ips, "count": ips.len()}))
}

fn parse_ip_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

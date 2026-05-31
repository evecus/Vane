use crate::api::AppState;
use crate::config::{db, types::*};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

pub async fn list(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.cfg.read();
    Json(cfg.port_forwards.clone())
}

#[derive(Deserialize)]
pub struct PortForwardReq {
    name: Option<String>,
    protocol: Option<String>,
    listen_port: Option<u16>,
    target_ip: Option<String>,
    target_port: Option<u16>,
    enabled: Option<bool>,
}

pub async fn create(
    State(state): State<AppState>,
    Json(req): Json<PortForwardReq>,
) -> impl IntoResponse {
    let listen_port = match req.listen_port {
        Some(p) if p > 0 => p,
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "listen_port required"}))).into_response(),
    };
    let target_ip = req.target_ip.unwrap_or_default();
    let target_port = req.target_port.unwrap_or(0);

    let rule = PortForwardRule {
        id: new_id(),
        name: req.name.unwrap_or_default(),
        protocol: req.protocol.unwrap_or_else(|| "tcp".into()),
        listen_port,
        target_ip,
        target_port,
        enabled: req.enabled.unwrap_or(false),
        created_at: now_rfc3339(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_port_forward(&dd, &rule) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    let enabled = rule.enabled;
    let id = rule.id.clone();
    state.cfg.write().port_forwards.push(rule.clone());

    if enabled {
        let _ = state.pf.start(&id);
    }

    (StatusCode::CREATED, Json(rule)).into_response()
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PortForwardReq>,
) -> impl IntoResponse {
    let exists = state.cfg.read().port_forwards.iter().any(|r| r.id == id);
    if !exists {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    }

    {
        let mut cfg = state.cfg.write();
        if let Some(r) = cfg.port_forwards.iter_mut().find(|r| r.id == id) {
            if let Some(v) = req.name { r.name = v; }
            if let Some(v) = req.protocol { r.protocol = v; }
            if let Some(v) = req.listen_port { r.listen_port = v; }
            if let Some(v) = req.target_ip { r.target_ip = v; }
            if let Some(v) = req.target_port { r.target_port = v; }
            if let Some(v) = req.enabled { r.enabled = v; }
        }
    }

    let rule = state.cfg.read().port_forwards.iter().find(|r| r.id == id).cloned();
    let Some(rule) = rule else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_port_forward(&dd, &rule) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    // Restart if was running or newly enabled
    state.pf.stop(&id);
    if rule.enabled {
        let _ = state.pf.start(&id);
    }

    Json(rule).into_response()
}

pub async fn delete_pf(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.pf.stop(&id);
    state.cfg.write().port_forwards.retain(|r| r.id != id);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::delete_port_forward(&dd, &id) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn toggle(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let enabled;
    {
        let mut cfg = state.cfg.write();
        if let Some(r) = cfg.port_forwards.iter_mut().find(|r| r.id == id) {
            r.enabled = !r.enabled;
            enabled = r.enabled;
        } else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        }
    }

    let rule = state.cfg.read().port_forwards.iter().find(|r| r.id == id).cloned();
    if let Some(rule) = rule {
        let dd = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd { let _ = db::save_port_forward(&dd, &rule); }
    }

    if enabled {
        let _ = state.pf.start(&id);
    } else {
        state.pf.stop(&id);
    }

    Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response()
}

pub async fn stats(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let snap = state.pf.get_stats(&id);
    let history = state.pf.get_history(&id);
    Json(serde_json::json!({
        "current": snap,
        "history": history,
    }))
}

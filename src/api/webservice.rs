use crate::api::AppState;
use crate::config::{db, types::*};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

// ─── Services ─────────────────────────────────────────────────────────────────

pub async fn list_services(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.cfg.read().web_services.clone())
}

#[derive(Deserialize)]
pub struct ServiceReq {
    name: Option<String>,
    listen_port: Option<u16>,
    enable_https: Option<bool>,
    enabled: Option<bool>,
}

pub async fn create_service(
    State(state): State<AppState>,
    Json(req): Json<ServiceReq>,
) -> impl IntoResponse {
    let listen_port = match req.listen_port {
        Some(p) if p > 0 => p,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "listen_port required"})),
            )
                .into_response()
        }
    };
    let svc = WebService {
        id: new_id(),
        name: req.name.unwrap_or_default(),
        listen_port,
        enable_https: req.enable_https.unwrap_or(true),
        enabled: req.enabled.unwrap_or(false),
        routes: vec![],
        created_at: now_rfc3339(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_web_service(&dd, &svc) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    let id = svc.id.clone();
    let enabled = svc.enabled;
    state.cfg.write().web_services.push(svc.clone());
    if enabled {
        let _ = state.ws.start(&id);
    }
    (StatusCode::CREATED, Json(svc)).into_response()
}

pub async fn update_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ServiceReq>,
) -> impl IntoResponse {
    // If the port is changing, verify the new port is available before we
    // stop the running service (avoids an unrecoverable stopped-with-no-port state).
    if let Some(new_port) = req.listen_port {
        let current_port = state
            .cfg
            .read()
            .web_services
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.listen_port);
        if let Some(current) = current_port {
            if current != new_port && !crate::config::types::is_port_available(new_port) {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": format!("端口 {} 已被占用", new_port)})),
                )
                    .into_response();
            }
        }
    }
    {
        let mut cfg = state.cfg.write();
        let Some(s) = cfg.web_services.iter_mut().find(|s| s.id == id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        };
        if let Some(v) = req.name {
            s.name = v;
        }
        if let Some(v) = req.listen_port {
            s.listen_port = v;
        }
        if let Some(v) = req.enable_https {
            s.enable_https = v;
        }
        if let Some(v) = req.enabled {
            s.enabled = v;
        }
    }

    let svc = state
        .cfg
        .read()
        .web_services
        .iter()
        .find(|s| s.id == id)
        .cloned();
    let Some(svc) = svc else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let _ = db::save_web_service(&dd, &svc);
    }

    state.ws.stop(&id);
    if svc.enabled {
        let _ = state.ws.start(&id);
    }
    Json(svc).into_response()
}

pub async fn delete_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Collect all route IDs before removing the service (needed for scope cleanup)
    let route_ids: Vec<String> = state
        .cfg
        .read()
        .web_services
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.routes.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default();

    state.ws.stop(&id);
    state.cfg.write().web_services.retain(|s| s.id != id);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::delete_web_service(&dd, &id) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }

    // Cascade: remove ip_filter scope entries for every route in this service.
    let mut all_modified: Vec<crate::config::types::IpFilterRule> = Vec::new();
    for route_id in &route_ids {
        let modified = state
            .cfg
            .clean_scopes_for_deleted_target("webservice", route_id);
        all_modified.extend(modified);
    }
    if !all_modified.is_empty() {
        if let Some(dd) = state.cfg.read().data_dir.clone() {
            // Deduplicate by rule id before persisting
            let mut seen = std::collections::HashSet::new();
            for rule in &all_modified {
                if seen.insert(rule.id.clone()) {
                    let _ = db::save_ip_filter_rule(&dd, rule);
                }
            }
        }
    }

    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn toggle_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let enabled;
    {
        let mut cfg = state.cfg.write();
        let Some(s) = cfg.web_services.iter_mut().find(|s| s.id == id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        };
        s.enabled = !s.enabled;
        enabled = s.enabled;
    }
    let svc = state
        .cfg
        .read()
        .web_services
        .iter()
        .find(|s| s.id == id)
        .cloned();
    if let Some(svc) = svc {
        let dd = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd {
            let _ = db::save_web_service(&dd, &svc);
        }
    }
    state.ws.stop(&id);
    if enabled {
        let _ = state.ws.start(&id);
    }
    Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response()
}

// ─── Routes ───────────────────────────────────────────────────────────────────

pub async fn list_routes(
    State(state): State<AppState>,
    Path(svc_id): Path<String>,
) -> impl IntoResponse {
    let cfg = state.cfg.read();
    let routes = cfg
        .web_services
        .iter()
        .find(|s| s.id == svc_id)
        .map(|s| s.routes.clone())
        .unwrap_or_default();
    Json(routes)
}

#[derive(Deserialize)]
pub struct RouteReq {
    name: Option<String>,
    domain: Option<String>,
    backend_url: Option<String>,
    enabled: Option<bool>,
    auth_enabled: Option<bool>,
    auth_user: Option<String>,
    auth_password: Option<String>, // plain text, hashed on server
}

pub async fn create_route(
    State(state): State<AppState>,
    Path(svc_id): Path<String>,
    Json(req): Json<RouteReq>,
) -> impl IntoResponse {
    let domain = req.domain.unwrap_or_default();
    let backend_url = req.backend_url.unwrap_or_default();
    let auth_enabled = req.auth_enabled.unwrap_or(false);

    let auth_pass_hash = if auth_enabled {
        match &req.auth_password {
            Some(pw) if !pw.is_empty() => match bcrypt::hash(pw, bcrypt::DEFAULT_COST) {
                Ok(h) => h,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            },
            _ => String::new(),
        }
    } else {
        String::new()
    };

    let mut route = WebRoute {
        id: new_id(),
        name: req.name.unwrap_or_default(),
        domain: domain.clone(),
        backend_url,
        enabled: req.enabled.unwrap_or(false),
        matched_cert_id: String::new(),
        cert_status: "no_cert".into(),
        auth_enabled,
        auth_user: req.auth_user.unwrap_or_default(),
        auth_pass_hash,
        created_at: now_rfc3339(),
    };

    // Match cert
    state.ws.match_route_cert(&svc_id, &mut route);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_web_route(&dd, &svc_id, &route) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }

    {
        let mut cfg = state.cfg.write();
        if let Some(svc) = cfg.web_services.iter_mut().find(|s| s.id == svc_id) {
            svc.routes.push(route.clone());
        }
    }

    (StatusCode::CREATED, Json(route)).into_response()
}

pub async fn update_route(
    State(state): State<AppState>,
    Path((svc_id, route_id)): Path<(String, String)>,
    Json(req): Json<RouteReq>,
) -> impl IntoResponse {
    let existing_hash;
    {
        let cfg = state.cfg.read();
        existing_hash = cfg
            .web_services
            .iter()
            .find(|s| s.id == svc_id)
            .and_then(|s| s.routes.iter().find(|r| r.id == route_id))
            .map(|r| r.auth_pass_hash.clone())
            .unwrap_or_default();
    }

    let auth_enabled = req.auth_enabled.unwrap_or(false);
    let new_hash = if auth_enabled {
        match &req.auth_password {
            Some(pw) if !pw.is_empty() => match bcrypt::hash(pw, bcrypt::DEFAULT_COST) {
                Ok(h) => h,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            },
            // Keep the existing hash only when one is already stored.
            // If there is no existing hash (first-time enable), a password is required.
            _ if !existing_hash.is_empty() => existing_hash,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "开启访问验证时必须设置密码"})),
                )
                    .into_response()
            }
        }
    } else {
        // Always wipe the hash when auth is turned off so a stale credential
        // can never accidentally re-enable the gate on the next toggle.
        String::new()
    };

    {
        let mut cfg = state.cfg.write();
        let Some(svc) = cfg.web_services.iter_mut().find(|s| s.id == svc_id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "service not found"})),
            )
                .into_response();
        };
        let Some(r) = svc.routes.iter_mut().find(|r| r.id == route_id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "route not found"})),
            )
                .into_response();
        };
        if let Some(v) = req.name {
            r.name = v;
        }
        if let Some(v) = req.domain {
            r.domain = v;
        }
        if let Some(v) = req.backend_url {
            r.backend_url = v;
        }
        if let Some(v) = req.enabled {
            r.enabled = v;
        }
        r.auth_enabled = auth_enabled;
        if let Some(v) = req.auth_user {
            r.auth_user = v;
        }
        r.auth_pass_hash = new_hash;
    }

    let route = {
        let cfg = state.cfg.read();
        cfg.web_services
            .iter()
            .find(|s| s.id == svc_id)
            .and_then(|s| s.routes.iter().find(|r| r.id == route_id))
            .cloned()
    };
    let Some(mut route) = route else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response();
    };

    state.ws.match_route_cert(&svc_id, &mut route);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let _ = db::save_web_route(&dd, &svc_id, &route);
    }

    Json(route).into_response()
}

pub async fn delete_route(
    State(state): State<AppState>,
    Path((svc_id, route_id)): Path<(String, String)>,
) -> impl IntoResponse {
    {
        let mut cfg = state.cfg.write();
        if let Some(svc) = cfg.web_services.iter_mut().find(|s| s.id == svc_id) {
            svc.routes.retain(|r| r.id != route_id);
        }
    }
    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let _ = db::delete_web_route(&dd, &route_id);
    }

    // Cascade: remove ip_filter scope entries referencing this route.
    let modified_rules = state
        .cfg
        .clean_scopes_for_deleted_target("webservice", &route_id);
    if !modified_rules.is_empty() {
        if let Some(dd) = state.cfg.read().data_dir.clone() {
            for rule in &modified_rules {
                let _ = db::save_ip_filter_rule(&dd, rule);
            }
        }
    }

    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn toggle_route(
    State(state): State<AppState>,
    Path((svc_id, route_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let enabled;
    {
        let mut cfg = state.cfg.write();
        let Some(svc) = cfg.web_services.iter_mut().find(|s| s.id == svc_id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        };
        let Some(r) = svc.routes.iter_mut().find(|r| r.id == route_id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "not found"})),
            )
                .into_response();
        };
        r.enabled = !r.enabled;
        enabled = r.enabled;
    }
    let route = {
        let cfg = state.cfg.read();
        cfg.web_services
            .iter()
            .find(|s| s.id == svc_id)
            .and_then(|s| s.routes.iter().find(|r| r.id == route_id))
            .cloned()
    };
    if let Some(route) = route {
        let dd = state.cfg.read().data_dir.clone();
        if let Some(dd) = dd {
            let _ = db::save_web_route(&dd, &svc_id, &route);
        }
    }
    Json(serde_json::json!({"ok": true, "enabled": enabled})).into_response()
}

// ─── Access logs ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LogsQuery {
    limit: Option<usize>,
}

pub async fn get_logs(
    State(state): State<AppState>,
    Path(svc_id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> impl IntoResponse {
    let logs = state.ws.get_logs(&svc_id, q.limit.unwrap_or(100));
    Json(logs)
}

pub async fn get_all_logs(
    State(state): State<AppState>,
    Query(q): Query<LogsQuery>,
) -> impl IntoResponse {
    let logs = state.ws.get_logs("", q.limit.unwrap_or(200));
    Json(logs)
}

use axum::{
    extract::{Multipart, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::{
    auth::{bcrypt_hash, bearer, generate_token, hash_password, verify_password},
    models::*,
    state::{new_id, now_rfc3339, AppState, VERSION},
};

include!(concat!(env!("OUT_DIR"), "/embedded_assets.rs"));

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":"unauthorized"})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error":"forbidden"})),
    )
        .into_response()
}

fn not_found(msg: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

fn bad_request(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

fn internal(msg: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

fn ok_json(v: serde_json::Value) -> Response {
    (StatusCode::OK, Json(v)).into_response()
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

fn client_ip_str(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

async fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    state.cleanup_security_state().await;
    if let Some(t) = bearer(headers) {
        if state.is_session_valid(&t).await {
            state.touch_session(&t).await;
            return true;
        }
    }
    false
}

async fn ipfilter_pass(
    state: &AppState,
    headers: &HeaderMap,
    scope_type: &str,
    target_id: &str,
) -> bool {
    let ip = match client_ip(headers) {
        Some(ip) => ip,
        None => return true,
    };

    let rules = state.data.read().await.ipfilter.clone();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        if !scope_matches(&rule.scopes, scope_type, target_id) {
            continue;
        }

        let mut all_ips: Vec<String> = rule.manual_ips.clone();
        for att in &rule.attachments {
            all_ips.extend(att.ips.clone());
        }

        let matched = ip_in_list(ip, &all_ips);
        return if rule.mode == "blacklist" {
            !matched
        } else {
            matched
        };
    }
    true
}

fn scope_matches(scopes: &[IpFilterScope], scope_type: &str, target_id: &str) -> bool {
    for s in scopes {
        if s.scope_type != scope_type {
            continue;
        }
        if s.target_id.is_empty() || s.target_id == target_id {
            return true;
        }
    }
    false
}

fn ip_in_list(ip: IpAddr, list: &[String]) -> bool {
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(net) = entry.parse::<ipnet::IpNet>() {
            if net.contains(&ip) {
                return true;
            }
        } else if let Ok(parsed) = entry.parse::<IpAddr>() {
            if parsed == ip {
                return true;
            }
        }
    }
    false
}

macro_rules! require_auth {
    ($state:expr, $headers:expr) => {
        if !authorized($state, $headers).await {
            return unauthorized();
        }
    };
}

macro_rules! require_admin_ipfilter {
    ($state:expr, $headers:expr) => {
        if !ipfilter_pass($state, $headers, "admin", "").await {
            return forbidden();
        }
    };
}

// ─── SPA Fallback / Static File Serving ──────────────────────────────────────

pub async fn spa_fallback(State(state): State<AppState>, req: Request) -> Response {
    let safe = state.config.read().await.admin.safe_entry.clone();
    let uri_path = req.uri().path().to_string();
    let mut p = uri_path.as_str();

    if p.starts_with("/api/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Assets bypass safe_entry check
    let always_allowed = uri_path.starts_with("/assets/")
        || matches!(
            uri_path.as_str(),
            "/favicon.svg"
                | "/favicon.ico"
                | "/favicon.png"
                | "/icon-192.png"
                | "/icon-512.png"
                | "/apple-touch-icon.png"
                | "/robots.txt"
                | "/manifest.json"
        );

    if !always_allowed && !safe.is_empty() {
        let prefix = format!("/{}", safe.trim_matches('/'));
        if p.starts_with(prefix.as_str()) {
            let stripped = &p[prefix.len()..];
            p = if stripped.is_empty() || stripped == "/" {
                "/"
            } else {
                stripped
            };
        } else if p != "/" {
            return (StatusCode::FORBIDDEN, "forbidden").into_response();
        }
    }

    let rel = if p == "/" || p.is_empty() {
        "index.html".to_string()
    } else {
        p.trim_start_matches('/').to_string()
    };

    // Try serving from embedded bytes first, then from disk
    serve_static_file(&rel).await
}

async fn serve_static_file(rel: &str) -> Response {
    // 1) Try embedded bytes (compiled into binary via build.rs)
    if let Some(bytes) = get_embedded(rel) {
        let ct = mime_type(rel);
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, ct)],
            bytes,
        )
            .into_response();
    }
    // Embedded SPA fallback (index.html)
    if let Some(bytes) = get_embedded("index.html") {
        let ct = "text/html; charset=utf-8";
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, ct)],
            bytes,
        )
            .into_response();
    }
    // 2) Fall back to disk (useful in development without embedding)
    let candidate_dirs = ["web/dist", "../web/dist", "./dist"];
    for dir in &candidate_dirs {
        let path = std::path::Path::new(dir).join(rel);
        if path.exists() && path.is_file() {
            if let Ok(bytes) = tokio::fs::read(&path).await {
                let ct = mime_type(rel);
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, ct)],
                    bytes,
                )
                    .into_response();
            }
        }
        // SPA fallback: serve index.html for unknown routes
        let index = std::path::Path::new(dir).join("index.html");
        if index.exists() {
            if let Ok(bytes) = tokio::fs::read(&index).await {
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    bytes,
                )
                    .into_response();
            }
        }
    }
    (
        StatusCode::NOT_FOUND,
        "Frontend not found. Build the web UI with: cd web && npm run build",
    )
        .into_response()
}

/// Returns embedded static file bytes. Populated by build.rs at compile time.
fn get_embedded(rel: &str) -> Option<Vec<u8>> {
    EMBEDDED_ASSETS.get(rel).map(|b| b.to_vec())
}

pub async fn serve_manifest(State(state): State<AppState>) -> Response {
    let entry = state.config.read().await.admin.safe_entry.clone();
    let start_url = if entry.is_empty() {
        "/".to_string()
    } else {
        format!("/{}/", entry.trim_matches('/'))
    };

    ok_json(serde_json::json!({
        "name": "Vane",
        "short_name": "Vane",
        "description": "Vane Network Manager",
        "start_url": start_url,
        "display": "standalone",
        "background_color": "#667eea",
        "theme_color": "#764ba2",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    }))
}

fn mime_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("json") => "application/json",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

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
    let ip = client_ip_str(&headers);

    // Rate limit: 10 attempts per 10 minutes per IP
    {
        let attempts = state.login_attempts.read().await;
        if let Some((count, ts)) = attempts.get(&ip) {
            if *count >= 10 && ts.elapsed().as_secs() < 600 {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"error":"登录尝试次数过多，请10分钟后重试"})),
                )
                    .into_response();
            }
        }
    }

    let cfg = state.config.read().await;
    let ok = req.username == cfg.admin.username
        && verify_password(&req.password, &cfg.admin.password_hash);
    drop(cfg);

    let _ = state.db.append_admin_log(&AdminLogRecord {
        ts: now_rfc3339(),
        ip: ip.clone(),
        action: "login".to_string(),
        success: ok,
    }).await;

    if !ok {
        let mut a = state.login_attempts.write().await;
        let e = a
            .entry(ip.clone())
            .or_insert((0, std::time::Instant::now()));
        e.0 += 1;
        e.1 = std::time::Instant::now();
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"用户名或密码错误"})),
        )
            .into_response();
    }

    state.login_attempts.write().await.remove(&ip);

    let token = generate_token();
    state.add_session(&token, &req.username).await;

    ok_json(serde_json::json!({"token": token}))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = bearer(&headers) {
        state.remove_session(&t).await;
    }
    ok_json(serde_json::json!({"ok": true}))
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

pub async fn list_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let sessions = state.db.load_sessions().await.unwrap_or_default();
    ok_json(serde_json::to_value(&sessions).unwrap_or_default())
}

pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    state.remove_session(&token).await;
    ok_json(serde_json::json!({"ok": true}))
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

pub async fn get_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let d = state.data.read().await;
    let certs_expiring_soon = d
        .tls
        .iter()
        .filter(|c| {
            let days = c.days_until_expiry();
            days >= 0 && days <= 30
        })
        .count();
    let stats = DashboardStats {
        port_forwards: d.portforward.len(),
        ddns: d.ddns.len(),
        web_services: d.webservice.len(),
        tls_certs: d.tls.len(),
        certs_expiring_soon,
    };
    ok_json(serde_json::to_value(&stats).unwrap_or_default())
}

pub async fn get_admin_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let logs = state.db.load_admin_logs(200).await.unwrap_or_default();
    ok_json(serde_json::to_value(&logs).unwrap_or_default())
}

pub async fn append_admin_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    require_auth!(&state, &headers);
    let rec = AdminLogRecord {
        ts: v["ts"].as_str().unwrap_or("").to_string(),
        ip: v["ip"].as_str().unwrap_or("").to_string(),
        action: v["action"].as_str().unwrap_or("").to_string(),
        success: v["success"].as_bool().unwrap_or(true),
    };
    let _ = state.db.append_admin_log(&rec).await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn query_admin_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let action = q.get("action").cloned().unwrap_or_default();
    let limit: usize = q
        .get("limit")
        .and_then(|x| x.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let mut logs = state.db.load_admin_logs(limit.max(1000)).await.unwrap_or_default();
    if !action.is_empty() {
        logs.retain(|x| x.action.contains(&action));
    }
    logs.truncate(limit);
    ok_json(serde_json::to_value(&logs).unwrap_or_default())
}

// ─── Settings ─────────────────────────────────────────────────────────────────

pub async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let cfg = state.config.read().await;
    let view = SettingsView {
        username: cfg.admin.username.clone(),
        port: cfg.admin.port,
        safe_entry: cfg.admin.safe_entry.clone(),
        welcome_shown: cfg.admin.welcome_shown,
        version: VERSION.to_string(),
    };
    ok_json(serde_json::to_value(&view).unwrap_or_default())
}

#[derive(Deserialize)]
pub struct UpdateSettingsReq {
    username: Option<String>,
    current_password: Option<String>,
    new_password: Option<String>,
    port: Option<u16>,
    safe_entry: Option<String>,
}

pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateSettingsReq>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    let mut cfg = state.config.write().await;
    let old_port = cfg.admin.port;
    let old_safe_entry = cfg.admin.safe_entry.clone();

    let username_change = req
        .username
        .as_ref()
        .map(|u| !u.is_empty() && u != &cfg.admin.username)
        .unwrap_or(false);
    let password_change = req
        .new_password
        .as_ref()
        .map(|p| !p.is_empty())
        .unwrap_or(false);

    if username_change || password_change {
        let cur = req.current_password.as_deref().unwrap_or("");
        if !verify_password(cur, &cfg.admin.password_hash) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error":"当前密码错误"})),
            )
                .into_response();
        }
    }

    if password_change {
        let new_pass = req.new_password.as_deref().unwrap_or("");
        match hash_password(new_pass) {
            Ok(h) => cfg.admin.password_hash = h,
            Err(_) => return internal("密码加密失败"),
        }
    }
    if let Some(u) = req.username.as_ref().filter(|u| !u.is_empty()) {
        cfg.admin.username = u.clone();
    }
    if let Some(p) = req.port.filter(|&p| p > 0) {
        cfg.admin.port = p;
    }
    if let Some(se) = req.safe_entry {
        cfg.admin.safe_entry = se.trim_matches('/').to_string();
    }

    let new_port = cfg.admin.port;
    let new_safe_entry = cfg.admin.safe_entry.clone();
    drop(cfg);

    if let Err(e) = state.db.save_admin(&state.config.read().await.admin).await {
        return internal(&format!("保存失败: {e}"));
    }

    let port_changed = new_port != old_port;
    let safe_entry_changed = new_safe_entry.trim_matches('/') != old_safe_entry.trim_matches('/');
    let needs_logout = port_changed || safe_entry_changed;

    if needs_logout {
        state.clear_all_sessions().await;
    }

    if port_changed {
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            eprintln!("[settings] port changed, restarting...");
            if let Ok(exe) = std::env::current_exe() {
                let args: Vec<String> = std::env::args().collect();
                let _ = std::process::Command::new(&exe).args(&args[1..]).spawn();
            }
            std::process::exit(0);
        });
    }

    ok_json(serde_json::json!({"ok": true, "restart": port_changed, "logout": needs_logout}))
}

pub async fn mark_welcome_shown(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    {
        state.config.write().await.admin.welcome_shown = true;
    }
    let _ = state.db.save_admin(&state.config.read().await.admin).await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn backup_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let admin = state.config.read().await.admin.clone();
    let data = state.data.read().await.clone();
    let blob = match state.db.export_backup(&data, &admin).await {
        Ok(b) => b,
        Err(e) => return internal(&format!("备份失败: {e}")),
    };
    let filename = format!(
        "vane-backup-{}.enc",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    );
    (
        StatusCode::OK,
        [
            (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
            (
                "content-disposition".to_string(),
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        blob,
    )
        .into_response()
}

pub async fn restore_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let backup = match state.db.import_backup(&body).await {
        Ok(b) => b,
        Err(e) => return bad_request(&format!("备份文件无效: {e}")),
    };
    if let Err(e) = state.db.restore_from_backup(&backup).await {
        return internal(&format!("恢复失败: {e}"));
    }
    // Reload in-memory state from DB
    let new_data = RuntimeData {
        portforward: backup.portforward.clone(),
        ddns: backup.ddns.clone(),
        webservice: backup.webservice.clone(),
        tls: backup.tls.clone(),
        ipfilter: backup.ipfilter.clone(),
        ..Default::default()
    };
    *state.config.write().await = Config { admin: backup.admin };
    *state.data.write().await = new_data;
    state.apply_engines().await;

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        if let Ok(exe) = std::env::current_exe() {
            let args: Vec<String> = std::env::args().collect();
            let _ = std::process::Command::new(&exe).args(&args[1..]).spawn();
        }
        std::process::exit(0);
    });

    ok_json(serde_json::json!({"ok": true, "message": "配置已恢复，程序即将重启"}))
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

pub async fn list_port_forwards(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    ok_json(serde_json::to_value(&state.data.read().await.portforward).unwrap_or_default())
}

pub async fn create_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut rule): Json<PortForwardRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    rule.normalize();
    let port = rule.effective_listen_port();
    if port == 0 {
        return bad_request("无效端口");
    }
    if rule.enabled && !is_port_available(port as u32) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":port})),
        )
            .into_response();
    }

    rule.id = new_id();
    rule.created_at = now_rfc3339();

    let mut d = state.data.write().await;
    d.portforward.push(rule.clone());
    drop(d);
    let _ = state.db.save_port_forward(&rule).await;
    if rule.enabled {
        state.apply_engines().await;
    }
    (StatusCode::CREATED, Json(rule)).into_response()
}

pub async fn update_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<PortForwardRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    req.normalize();
    let port = req.effective_listen_port();
    // Stop existing engine so port is freed before availability check
    state
        .engines
        .portforward
        .write()
        .await
        .remove(&id)
        .map(|tx| tx.send(()));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    if req.enabled && !is_port_available(port as u32) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":port})),
        )
            .into_response();
    }

    let mut d = state.data.write().await;
    match d.portforward.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            req.id = id.clone();
            req.created_at = x.created_at.clone();
            if req.protocol.is_empty() {
                req.protocol = x.protocol.clone();
            }
            *x = req.clone();
        }
    }
    drop(d);
    let _ = state.db.save_port_forward(&req).await;
    state.apply_engines().await;
    ok_json(serde_json::to_value(&req).unwrap_or_default())
}

pub async fn delete_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    d.portforward.retain(|x| x.id != id);
    clean_scopes_for_deleted_target(&mut d.ipfilter, "portforward", &id);
    // Persist updated ip_filter rules (scope cleanup)
    let ipf_snapshot = d.ipfilter.clone();
    drop(d);
    let _ = state.db.delete_port_forward(&id).await;
    for rule in &ipf_snapshot { let _ = state.db.save_ip_filter(rule).await; }
    state.apply_engines().await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_port_forward(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    let mut d = state.data.write().await;
    let rule = match d.portforward.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            x.enabled = !x.enabled;
            x.clone()
        }
    };
    let enabled = rule.enabled;
    let port = rule.effective_listen_port();

    if enabled && port > 0 && !is_port_available(port as u32) {
        if let Some(x) = d.portforward.iter_mut().find(|x| x.id == id) {
            x.enabled = false;
        }
        let snap = d.portforward.iter().find(|x| x.id == id).cloned();
        drop(d);
        if let Some(r) = snap { let _ = state.db.save_port_forward(&r).await; }
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":port})),
        )
            .into_response();
    }
    drop(d);
    let _ = state.db.save_port_forward(&rule).await;
    state.apply_engines().await;
    ok_json(serde_json::json!({"enabled": enabled}))
}

pub async fn get_port_forward_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    let exists = state
        .data
        .read()
        .await
        .portforward
        .iter()
        .any(|x| x.id == id);
    if !exists {
        return not_found("not found");
    }
    let history = state.engines.get_pf_history(&id).await;
    ok_json(serde_json::json!({"history": history}))
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

pub async fn list_ddns(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    ok_json(serde_json::to_value(&state.data.read().await.ddns).unwrap_or_default())
}

pub async fn create_ddns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut rule): Json<DdnsRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    rule.id = new_id();
    rule.created_at = now_rfc3339();
    let mut d = state.data.write().await;
    d.ddns.push(rule.clone());
    drop(d);
    let _ = state.db.save_ddns(&rule).await;
    if rule.enabled {
        state.apply_engines().await;
    }
    (StatusCode::CREATED, Json(rule)).into_response()
}

pub async fn update_ddns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<DdnsRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    match d.ddns.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            req.id = id.clone();
            req.created_at = x.created_at.clone();
            req.last_ip = x.last_ip.clone();
            req.last_updated = x.last_updated.clone();
            req.ip_history = x.ip_history.clone();
            req.last_sync_ok = x.last_sync_ok;
            req.last_sync_err = x.last_sync_err.clone();
            req.last_sync_at = x.last_sync_at.clone();
            *x = req.clone();
        }
    }
    drop(d);
    let _ = state.db.save_ddns(&req).await;
    state.apply_engines().await;
    ok_json(serde_json::to_value(&req).unwrap_or_default())
}

pub async fn delete_ddns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    d.ddns.retain(|x| x.id != id);
    drop(d);
    let _ = state.db.delete_ddns(&id).await;
    state.apply_engines().await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_ddns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    let enabled = match d.ddns.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            x.enabled = !x.enabled;
            x.enabled
        }
    };
    drop(d);
    let snap = state.data.read().await.ddns.iter().find(|x| x.id == id).cloned();
    if let Some(r) = snap { let _ = state.db.save_ddns(&r).await; }
    state.apply_engines().await;
    ok_json(serde_json::json!({"enabled": enabled}))
}

pub async fn update_ddns_refresh_now(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let rule = state
        .data
        .read()
        .await
        .ddns
        .iter()
        .find(|x| x.id == id)
        .cloned();
    match rule {
        None => not_found("not found"),
        Some(r) => {
            let client = reqwest::Client::new();
            match crate::engines::sync_ddns_provider(&client, &r).await {
                Ok(ip) => {
                    let at = now_rfc3339();
                    let mut d = state.data.write().await;
                    if let Some(x) = d.ddns.iter_mut().find(|x| x.id == id) {
                        x.last_ip = ip.clone();
                        x.last_updated = at.clone();
                        x.last_sync_ok = Some(true);
                        x.last_sync_err.clear();
                        x.last_sync_at = at.clone();
                        x.ip_history.push(IpRecord {
                            ip: ip.clone(),
                            timestamp: at,
                        });
                        if x.ip_history.len() > 100 {
                            let n = x.ip_history.len() - 100;
                            x.ip_history.drain(0..n);
                        }
                    }
                    let updated = d.ddns.iter().find(|x| x.id == id).cloned();
                    drop(d);
                    if let Some(r) = updated { let _ = state.db.save_ddns(&r).await; }
                    ok_json(serde_json::json!({"ok": true, "ip": ip}))
                }
                Err(e) => {
                    let at = now_rfc3339();
                    let mut d = state.data.write().await;
                    if let Some(x) = d.ddns.iter_mut().find(|x| x.id == id) {
                        x.last_sync_ok = Some(false);
                        x.last_sync_err = e.to_string();
                        x.last_sync_at = at;
                    }
                    let updated = d.ddns.iter().find(|x| x.id == id).cloned();
                    drop(d);
                    if let Some(r) = updated { let _ = state.db.save_ddns(&r).await; }
                    internal(&e.to_string())
                }
            }
        }
    }
}

pub async fn list_interfaces(State(_state): State<AppState>, _headers: HeaderMap) -> Response {
    let ifaces = get_network_interfaces();
    ok_json(serde_json::to_value(&ifaces).unwrap_or_default())
}

pub async fn list_iface_ips(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let iface = q.get("iface").cloned().unwrap_or_default();
    if iface.is_empty() {
        return bad_request("iface required");
    }
    let version = q
        .get("version")
        .cloned()
        .unwrap_or_else(|| "ipv4".to_string());
    let ips = collect_iface_ips(&iface, &version);
    ok_json(serde_json::to_value(&ips).unwrap_or_default())
}

fn get_network_interfaces() -> Vec<String> {
    // Try Linux /proc/net/dev first
    if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
        let mut ifaces: Vec<String> = content
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        ifaces.sort();
        return ifaces;
    }
    vec!["eth0".to_string(), "lo".to_string()]
}

pub fn collect_iface_ips(iface: &str, version: &str) -> Vec<String> {
    let mut ips = vec![];

    if version == "ipv6" || version == "all" {
        if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 && parts[5] == iface {
                    if let Ok(addr) = parse_proc_ipv6(parts[0]) {
                        ips.push(addr);
                    }
                }
            }
        }
    }

    if version == "ipv4" || version == "all" {
        // Use getifaddrs via /proc/net/fib_trie + /proc/net/if_inet
        // More reliable: read from /proc/net/fib_trie with interface association
        let addrs = collect_ipv4_for_iface(iface);
        ips.extend(addrs);

        if ips.is_empty() {
            // Minimal fallback
        }
    }

    ips
}

fn collect_ipv4_for_iface(iface: &str) -> Vec<String> {
    // Read /proc/net/fib_trie for host routes, then verify via /proc/net/if_inet
    // Most reliable: parse /proc/net/fib_trie for HOST entries
    let mut result = vec![];

    // Try reading from /sys/class/net/<iface>/address to get interface existence
    let iface_path = format!("/sys/class/net/{iface}");
    if !std::path::Path::new(&iface_path).exists() {
        return result;
    }

    // Parse /proc/net/fib_trie - it doesn't map IPs to interfaces directly
    // Better approach: read /proc/net/if_inet (non-standard) or use getifaddrs
    // Use cross-platform approach via std::net
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") {
            let lines: Vec<&str> = content.lines().collect();
            let mut i = 0;
            let mut candidates: Vec<String> = vec![];
            while i < lines.len() {
                let line = lines[i].trim();
                // Look for /32 HOST entries
                if line.contains("HOST") {
                    if i > 0 {
                        let prev = lines[i - 1].trim();
                        let ip_part = prev.split_whitespace().next().unwrap_or("");
                        if ip_part.contains('.') {
                            if let Ok(ip) = ip_part.parse::<std::net::Ipv4Addr>() {
                                if !ip.is_loopback() {
                                    candidates.push(ip.to_string());
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
            result = candidates;
        }
    }

    result
}

fn parse_proc_ipv6(hex: &str) -> anyhow::Result<String> {
    if hex.len() != 32 {
        anyhow::bail!("invalid hex len");
    }
    let mut groups = vec![];
    for i in 0..8 {
        let g = u16::from_str_radix(&hex[i * 4..(i + 1) * 4], 16)?;
        groups.push(format!("{g:x}"));
    }
    Ok(groups.join(":"))
}

// ─── Web Service ──────────────────────────────────────────────────────────────

pub async fn list_webservices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let d = state.data.read().await;
    let svcs: Vec<_> = d
        .webservice
        .iter()
        .map(|svc| {
            let mut s = svc.clone();
            for route in &mut s.routes {
                if !route.auth_pass_hash.is_empty() {
                    route.auth_pass_hash = "set".to_string();
                }
            }
            s
        })
        .collect();
    ok_json(serde_json::to_value(&svcs).unwrap_or_default())
}

pub async fn create_webservice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut svc): Json<WebServiceRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    if svc.listen_port == 0 {
        return bad_request("无效端口");
    }
    if svc.enabled && !is_port_available(svc.listen_port as u32) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":svc.listen_port})),
        )
            .into_response();
    }

    svc.id = new_id();
    svc.created_at = now_rfc3339();

    let mut d = state.data.write().await;
    d.webservice.push(svc.clone());
    drop(d);
    let _ = state.db.save_web_service(&svc).await;
    if svc.enabled {
        state.apply_engines().await;
    }
    (StatusCode::CREATED, Json(svc)).into_response()
}

pub async fn update_webservice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<WebServiceRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    state
        .engines
        .webservice
        .write()
        .await
        .remove(&id)
        .map(|tx| tx.send(()));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    if req.enabled && !is_port_available(req.listen_port as u32) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":req.listen_port})),
        )
            .into_response();
    }

    let mut d = state.data.write().await;
    match d.webservice.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            req.id = id.clone();
            req.created_at = x.created_at.clone();
            if req.routes.is_empty() {
                req.routes = x.routes.clone();
            }
            *x = req.clone();
        }
    }
    drop(d);
    let _ = state.db.save_web_service(&req).await;
    state.apply_engines().await;
    ok_json(serde_json::to_value(&req).unwrap_or_default())
}

pub async fn delete_webservice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    let route_ids: Vec<String> = d
        .webservice
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.routes.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default();
    d.webservice.retain(|x| x.id != id);
    for rid in route_ids {
        clean_scopes_for_deleted_target(&mut d.ipfilter, "webservice", &rid);
    }
    let ipf_snap = d.ipfilter.clone();
    drop(d);
    let _ = state.db.delete_web_service(&id).await;
    for rule in &ipf_snap { let _ = state.db.save_ip_filter(rule).await; }
    state.apply_engines().await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_webservice(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    let (enabled, port) = match d.webservice.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            x.enabled = !x.enabled;
            (x.enabled, x.listen_port)
        }
    };
    if enabled && port > 0 && !is_port_available(port as u32) {
        // Roll back
        if let Some(x) = d.webservice.iter_mut().find(|x| x.id == id) {
            x.enabled = false;
        }
        let svc_snap = d.webservice.iter().find(|x| x.id == id).cloned();
        drop(d);
        if let Some(svc) = svc_snap { let _ = state.db.save_web_service(&svc).await; }
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"端口已被占用","port":port})),
        )
            .into_response();
    }
    let svc_snap = d.webservice.iter().find(|x| x.id == id).cloned();
    drop(d);
    if let Some(svc) = &svc_snap { let _ = state.db.save_web_service(svc).await; }

    if enabled {
        // Check that at least one enabled route has a matched cert (when HTTPS enabled)
        let has_valid_routes = svc_snap.as_ref().map(|s| {
            if !s.enable_https { return true; }
            s.routes.iter().any(|r| r.enabled && r.cert_status == "ok")
        }).unwrap_or(false);
        if svc_snap.as_ref().map(|s| s.enable_https).unwrap_or(false) && !has_valid_routes {
            // Roll back enabled state
            let mut d = state.data.write().await;
            if let Some(x) = d.webservice.iter_mut().find(|x| x.id == id) {
                x.enabled = false;
                let snap = x.clone();
                drop(d);
                let _ = state.db.save_web_service(&snap).await;
            } else {
                drop(d);
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"请先添加子规则，证书匹配成功后方可启动"})),
            ).into_response();
        }
    }

    state.apply_engines().await;
    ok_json(serde_json::json!({"enabled": enabled}))
}

// ─── Web Routes ───────────────────────────────────────────────────────────────

pub async fn list_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    let d = state.data.read().await;
    match d.webservice.iter().find(|s| s.id == id) {
        None => not_found("service not found"),
        Some(svc) => {
            let routes: Vec<_> = svc
                .routes
                .iter()
                .map(|r| {
                    let mut r = r.clone();
                    if !r.auth_pass_hash.is_empty() {
                        r.auth_pass_hash = "set".to_string();
                    }
                    r
                })
                .collect();
            ok_json(serde_json::to_value(&routes).unwrap_or_default())
        }
    }
}

#[derive(Deserialize)]
pub struct RouteReq {
    #[serde(flatten)]
    pub route: WebRoute,
    #[serde(default)]
    pub auth_pass: String,
}

pub async fn create_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(svc_id): Path<String>,
    Json(req): Json<RouteReq>,
) -> Response {
    require_auth!(&state, &headers);
    let mut route = req.route;
    route.id = new_id();
    route.created_at = now_rfc3339();

    if route.auth_enabled {
        if route.auth_user.is_empty() || req.auth_pass.is_empty() {
            return bad_request("开启访问验证时，账号和密码不能为空");
        }
        match bcrypt_hash(&req.auth_pass) {
            Ok(h) => route.auth_pass_hash = h,
            Err(_) => return internal("密码加密失败"),
        }
    } else {
        route.auth_user.clear();
        route.auth_pass_hash.clear();
    }

    // Match cert before saving
    {
        let d = state.data.read().await;
        match crate::engines::find_tls_cert(&d.tls, &route.domain) {
            Some(cert) => {
                route.matched_cert_id = cert.id.clone();
                route.cert_status = if cert.status == "active" {
                    "ok".to_string()
                } else {
                    "cert_inactive".to_string()
                };
            }
            None => {
                route.matched_cert_id.clear();
                route.cert_status = "no_cert".to_string();
            }
        }
    }

    let mut d = state.data.write().await;
    match d.webservice.iter_mut().find(|s| s.id == svc_id) {
        None => return not_found("service not found"),
        Some(svc) => svc.routes.push(route.clone()),
    }
    drop(d);
    let _ = state.db.save_web_route(&svc_id, &route).await;
    state.apply_engines().await;

    let mut resp = route.clone();
    resp.auth_pass_hash.clear();
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn update_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((svc_id, rid)): Path<(String, String)>,
    Json(req): Json<RouteReq>,
) -> Response {
    require_auth!(&state, &headers);
    let mut route = req.route;

    let mut d = state.data.write().await;

    // Validate service and get existing route data (need clone to avoid borrow conflicts)
    let (existing, tls_rules_clone) = {
        let svc = match d.webservice.iter().find(|s| s.id == svc_id) {
            None => return not_found("service not found"),
            Some(s) => s,
        };
        let existing = match svc.routes.iter().find(|r| r.id == rid) {
            None => return not_found("route not found"),
            Some(r) => r.clone(),
        };
        (existing, d.tls.clone())
    };

    route.id = rid.clone();
    route.created_at = existing.created_at.clone();

    if route.auth_enabled {
        if route.auth_user.is_empty() {
            return bad_request("开启访问验证时，账号不能为空");
        }
        if req.auth_pass.is_empty() && existing.auth_pass_hash.is_empty() {
            return bad_request("开启访问验证时，密码不能为空");
        }
        if req.auth_pass.is_empty() {
            route.auth_pass_hash = existing.auth_pass_hash.clone();
        } else {
            match bcrypt_hash(&req.auth_pass) {
                Ok(h) => route.auth_pass_hash = h,
                Err(_) => return internal("密码加密失败"),
            }
        }
    } else {
        route.auth_user.clear();
        route.auth_pass_hash.clear();
    }

    // Match cert using cloned TLS rules (avoids borrow conflict with mutable d)
    match crate::engines::find_tls_cert(&tls_rules_clone, &route.domain) {
        Some(cert) => {
            route.matched_cert_id = cert.id.clone();
            route.cert_status = if cert.status == "active" {
                "ok".to_string()
            } else {
                "cert_inactive".to_string()
            };
        }
        None => {
            route.matched_cert_id.clear();
            route.cert_status = "no_cert".to_string();
        }
    }

    if let Some(svc) = d.webservice.iter_mut().find(|s| s.id == svc_id) {
        if let Some(r) = svc.routes.iter_mut().find(|r| r.id == rid) {
            *r = route.clone();
        }
    }
    drop(d);
    let _ = state.db.save_web_route(&svc_id, &route).await;
    state.apply_engines().await;

    let mut resp = route.clone();
    resp.auth_pass_hash.clear();
    ok_json(serde_json::to_value(&resp).unwrap_or_default())
}

pub async fn delete_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((svc_id, rid)): Path<(String, String)>,
) -> Response {
    require_auth!(&state, &headers);
    let mut d = state.data.write().await;
    if let Some(svc) = d.webservice.iter_mut().find(|s| s.id == svc_id) {
        svc.routes.retain(|r| r.id != rid);
    }
    clean_scopes_for_deleted_target(&mut d.ipfilter, "webservice", &rid);
    let ipf_snap = d.ipfilter.clone();
    drop(d);
    let _ = state.db.delete_web_route(&rid).await;
    for rule in &ipf_snap { let _ = state.db.save_ip_filter(rule).await; }
    state.apply_engines().await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((svc_id, rid)): Path<(String, String)>,
) -> Response {
    require_auth!(&state, &headers);
    let mut d = state.data.write().await;
    let svc = match d.webservice.iter_mut().find(|s| s.id == svc_id) {
        None => return not_found("service not found"),
        Some(s) => s,
    };
    let enabled = match svc.routes.iter_mut().find(|r| r.id == rid) {
        None => return not_found("route not found"),
        Some(r) => {
            r.enabled = !r.enabled;
            r.enabled
        }
    };
    drop(d);
    {
        let d2 = state.data.read().await;
        if let Some(svc) = d2.webservice.iter().find(|s| s.id == svc_id) {
            if let Some(r) = svc.routes.iter().find(|r| r.id == rid) {
                let r = r.clone(); let sid = svc_id.clone();
                drop(d2);
                let _ = state.db.save_web_route(&sid, &r).await;
            }
        }
    }
    state.apply_engines().await;
    ok_json(serde_json::json!({"enabled": enabled}))
}

// ─── Access Logs ──────────────────────────────────────────────────────────────

pub async fn get_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    let logs = state.db.load_access_logs(Some(&id), 200).await.unwrap_or_default();
    ok_json(serde_json::to_value(&logs).unwrap_or_default())
}

pub async fn get_all_access_logs(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    let logs = state.db.load_access_logs(None, 500).await.unwrap_or_default();
    ok_json(serde_json::to_value(&logs).unwrap_or_default())
}

pub async fn query_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    require_auth!(&state, &headers);
    let service = q.get("service_id").cloned().unwrap_or_default();
    let path_kw = q.get("path").cloned().unwrap_or_default();
    let limit: usize = q
        .get("limit")
        .and_then(|x| x.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let sid = if service.is_empty() { None } else { Some(service.as_str()) };
    let mut logs = state.db.load_access_logs(sid, limit.max(1000)).await.unwrap_or_default();
    if !path_kw.is_empty() {
        logs.retain(|x| x.domain.contains(&path_kw));
    }
    logs.truncate(limit);
    ok_json(serde_json::to_value(&logs).unwrap_or_default())
}

pub async fn append_access_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    require_auth!(&state, &headers);
    let log = AccessLog {
        id: v["id"].as_str().unwrap_or("").to_string(),
        service_id: v["service_id"].as_str().unwrap_or("").to_string(),
        route_id: v["route_id"].as_str().unwrap_or("").to_string(),
        route_name: v["route_name"].as_str().unwrap_or("").to_string(),
        domain: v["domain"].as_str().unwrap_or("").to_string(),
        status_code: v["status_code"].as_u64().unwrap_or(200) as u16,
        client_ip: v["client_ip"].as_str().unwrap_or("").to_string(),
        user_agent: v["user_agent"].as_str().unwrap_or("").to_string(),
        auth_result: v["auth_result"].as_str().unwrap_or("").to_string(),
        time: v["time"].as_str().unwrap_or("").to_string(),
    };
    let _ = state.db.append_access_log(&log).await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn clear_access_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    let _ = state.db.clear_access_logs(&id).await;
    ok_json(serde_json::json!({"ok": true}))
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

pub async fn list_tls(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let views: Vec<TlsCertView> = state
        .data
        .read()
        .await
        .tls
        .iter()
        .map(TlsCertView::from)
        .collect();
    ok_json(serde_json::to_value(&views).unwrap_or_default())
}

pub async fn create_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut cert): Json<TlsRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    cert.id = new_id();
    cert.created_at = now_rfc3339();
    if cert.status.is_empty() {
        cert.status = "pending".to_string();
    }
    let mut d = state.data.write().await;
    d.tls.push(cert.clone());
    drop(d);
    let _ = state.db.save_tls_cert(&cert).await;
    // Trigger route rematch so new cert is picked up
    let state2 = state.clone();
    tokio::spawn(async move {
        state2.rematch_and_restart().await;
    });
    let view = TlsCertView::from(&cert);
    (StatusCode::CREATED, Json(view)).into_response()
}

pub async fn update_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut req): Json<TlsRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    match d.tls.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            req.id = id.clone();
            req.created_at = x.created_at.clone();
            if req.cert_pem.is_empty() {
                req.cert_pem = x.cert_pem.clone();
                req.key_pem = x.key_pem.clone();
                req.issued_at = x.issued_at.clone();
                req.expires_at = x.expires_at.clone();
                if req.status.is_empty() {
                    req.status = x.status.clone();
                }
            }
            *x = req.clone();
        }
    }
    drop(d);
    let _ = state.db.save_tls_cert(&req).await;
    let state2 = state.clone();
    tokio::spawn(async move {
        state2.rematch_and_restart().await;
    });
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn delete_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    d.tls.retain(|x| x.id != id);
    drop(d);
    let _ = state.db.delete_tls_cert(&id).await;
    let state2 = state.clone();
    tokio::spawn(async move {
        state2.rematch_and_restart().await;
    });
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    let enabled = match d.tls.iter_mut().find(|x| x.id == id) {
        None => return not_found("not found"),
        Some(x) => {
            x.enabled = !x.enabled;
            x.enabled
        }
    };
    drop(d);
    {
        let snap = state.data.read().await.tls.iter().find(|x| x.id == id).cloned();
        if let Some(c) = snap { let _ = state.db.save_tls_cert(&c).await; }
    }
    let state2 = state.clone();
    tokio::spawn(async move {
        state2.rematch_and_restart().await;
    });
    ok_json(serde_json::json!({"enabled": enabled}))
}

pub async fn issue_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    let cert = {
        let mut d = state.data.write().await;
        match d.tls.iter_mut().find(|x| x.id == id) {
            None => return not_found("cert not found"),
            Some(x) => {
                x.status = "pending".to_string();
                x.error_msg.clear();
                x.clone()
            }
        }
    };
    let _ = state.db.save_tls_cert(&cert).await;

    let state2 = state.clone();
    let id2 = id.clone();
    tokio::spawn(async move {
        match crate::acme::issue_cert(&cert).await {
            Ok((cert_pem, key_pem, issued_at, expires_at)) => {
                let updated = {
                    let mut d = state2.data.write().await;
                    if let Some(x) = d.tls.iter_mut().find(|x| x.id == id2) {
                        x.cert_pem = cert_pem;
                        x.key_pem = key_pem;
                        x.issued_at = issued_at;
                        x.expires_at = expires_at;
                        x.status = "active".to_string();
                        x.error_msg.clear();
                        Some(x.clone())
                    } else { None }
                };
                if let Some(c) = updated { let _ = state2.db.save_tls_cert(&c).await; }
                state2.rematch_and_restart().await;
            }
            Err(e) => {
                eprintln!("[tls] issue {} failed: {e}", id2);
                let updated = {
                    let mut d = state2.data.write().await;
                    if let Some(x) = d.tls.iter_mut().find(|x| x.id == id2) {
                        x.status = "error".to_string();
                        x.error_msg = e.to_string();
                        Some(x.clone())
                    } else { None }
                };
                if let Some(c) = updated { let _ = state2.db.save_tls_cert(&c).await; }
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"ok": true, "message": "证书申请已开始，请稍后刷新查看状态"})),
    )
        .into_response()
}

pub async fn renew_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    issue_tls(State(state), headers, Path(id)).await
}

pub async fn upload_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    let mut zip_bytes: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        let fname = field.file_name().unwrap_or("").to_lowercase();
        let data = match field.bytes().await {
            Ok(b) => b.to_vec(),
            Err(_) => continue,
        };
        if fname.ends_with(".zip") || field_name == "file" {
            zip_bytes = Some(data);
        }
    }

    let zip_data = match zip_bytes {
        Some(d) => d,
        None => return bad_request("请上传证书 ZIP 文件"),
    };

    use std::io::Read;
    let cursor = std::io::Cursor::new(&zip_data);
    let mut zr = match zip::ZipArchive::new(cursor) {
        Ok(z) => z,
        Err(e) => return bad_request(&format!("无法解析 ZIP 文件: {e}")),
    };

    let mut cert_pem = String::new();
    let mut key_pem = String::new();
    let mut issuer_pem = String::new();

    for i in 0..zr.len() {
        let mut zf = match zr.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let fname = zf.name().to_lowercase();
        let fname = std::path::Path::new(&fname)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let ext = fname.rsplit('.').next().unwrap_or("").to_string();
        let mut content = String::new();
        let _ = zf.read_to_string(&mut content);

        match fname.as_str() {
            "cert.pem" | "fullchain.pem" | "certificate.pem" => {
                cert_pem = content;
                continue;
            }
            "key.pem" | "privkey.pem" | "private.pem" | "privatekey.pem" => {
                key_pem = content;
                continue;
            }
            _ => {}
        }
        match ext.as_str() {
            "key" => key_pem = content,
            "crt" | "pem" | "cer" => {
                if fname.contains("issuer") || fname.contains("ca") {
                    issuer_pem = content;
                } else if cert_pem.is_empty() {
                    cert_pem = content;
                }
            }
            _ => {}
        }
    }

    if !issuer_pem.is_empty() && !cert_pem.is_empty() {
        cert_pem = format!("{cert_pem}{issuer_pem}");
    }

    if cert_pem.is_empty() || key_pem.is_empty() {
        return bad_request("ZIP 中未找到证书文件（支持 .crt/.pem/.key 或 cert.pem/key.pem 格式）");
    }

    if let Err(e) = validate_cert_key(&cert_pem, &key_pem) {
        return bad_request(&format!("无效的证书或私钥: {e}"));
    }

    let domains = extract_domains_from_cert(&cert_pem);
    let expires_at = extract_expiry_from_cert(&cert_pem).unwrap_or_default();
    let domain = domains.first().cloned().unwrap_or_default();

    let cert = TlsRule {
        id: new_id(),
        name: domain.clone(),
        domain: domain.clone(),
        domains,
        source: "manual".to_string(),
        cert_pem,
        key_pem,
        issued_at: now_rfc3339(),
        expires_at,
        auto_renew: false,
        status: "active".to_string(),
        created_at: now_rfc3339(),
        enabled: true,
        ..Default::default()
    };

    let mut d = state.data.write().await;
    d.tls.push(cert.clone());
    drop(d);
    let _ = state.db.save_tls_cert(&cert).await;
    let state2 = state.clone();
    tokio::spawn(async move {
        state2.rematch_and_restart().await;
    });

    let view = TlsCertView::from(&cert);
    (StatusCode::CREATED, Json(view)).into_response()
}

pub async fn download_tls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    let cert = state
        .data
        .read()
        .await
        .tls
        .iter()
        .find(|x| x.id == id)
        .cloned();
    match cert {
        None => not_found("cert not found"),
        Some(c) => {
            if c.cert_pem.is_empty() || c.key_pem.is_empty() {
                return bad_request("证书尚未签发，无法下载");
            }
            let safe_name = sanitize_filename(&c.domain);
            let safe_name = if safe_name.is_empty() {
                "cert".to_string()
            } else {
                safe_name
            };
            let zip_bytes = build_cert_zip(&c, &safe_name);
            (
                StatusCode::OK,
                [
                    ("content-type".to_string(), "application/zip".to_string()),
                    (
                        "content-disposition".to_string(),
                        format!("attachment; filename=\"{safe_name}-certs.zip\""),
                    ),
                ],
                zip_bytes,
            )
                .into_response()
        }
    }
}

pub async fn get_tls_pem(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    match state
        .data
        .read()
        .await
        .tls
        .iter()
        .find(|x| x.id == id)
        .cloned()
    {
        None => not_found("cert not found"),
        Some(c) => ok_json(
            serde_json::json!({"cert_pem": c.cert_pem, "key_pem": c.key_pem, "domain": c.domain}),
        ),
    }
}

// ─── TLS helpers ──────────────────────────────────────────────────────────────

fn extract_domains_from_cert(pem_str: &str) -> Vec<String> {
    use base64::Engine;
    let b64: String = pem_str
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = match base64::engine::general_purpose::STANDARD.decode(&b64) {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) {
        let mut domains: Vec<String> = vec![];
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    if !domains.contains(&dns.to_string()) {
                        domains.push(dns.to_string());
                    }
                }
            }
        }
        if domains.is_empty() {
            if let Some(cn) = cert.subject().iter_common_name().next() {
                if let Ok(s) = cn.as_str() {
                    domains.push(s.to_string());
                }
            }
        }
        return domains;
    }
    vec![]
}

fn extract_expiry_from_cert(pem_str: &str) -> Option<String> {
    use base64::Engine;
    let b64: String = pem_str
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    let dt = chrono::DateTime::from_timestamp(ts, 0)?;
    Some(dt.to_rfc3339())
}

fn validate_cert_key(cert_pem: &str, key_pem: &str) -> anyhow::Result<()> {
    if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
        anyhow::bail!("invalid certificate PEM");
    }
    if !key_pem.contains("-----BEGIN") || !key_pem.contains("KEY-----") {
        anyhow::bail!("invalid private key PEM");
    }
    Ok(())
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '*' => '_',
            '"' | '\r' | '\n' | '\\' | '/' | ':' | '?' | '<' | '>' | '|' => '\0',
            other => other,
        })
        .filter(|c| *c != '\0')
        .collect()
}

fn split_cert_chain(pem_chain: &str) -> (String, String) {
    let mut server = String::new();
    let mut issuer = String::new();
    let mut rest = pem_chain;
    let mut first = true;
    loop {
        if let Some(start) = rest.find("-----BEGIN") {
            let chunk = &rest[start..];
            if let Some(end) = chunk.find("-----END") {
                if let Some(end2) = chunk[end..].find("-----\n") {
                    let block = &chunk[..end + end2 + 6];
                    if first {
                        server = block.to_string();
                        first = false;
                    } else {
                        issuer.push_str(block);
                    }
                    rest = &chunk[end + end2 + 6..];
                    continue;
                }
            }
        }
        break;
    }
    (server, issuer)
}

fn build_cert_zip(cert: &TlsRule, safe_name: &str) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        let (server_cert, issuer_cert) = split_cert_chain(&cert.cert_pem);

        if !issuer_cert.is_empty() {
            let full_chain = format!("{server_cert}{issuer_cert}");
            let _ = zw.start_file(format!("{safe_name}.crt"), opts);
            let _ = zw.write_all(full_chain.as_bytes());
            let _ = zw.start_file(format!("{safe_name}.pem"), opts);
            let _ = zw.write_all(full_chain.as_bytes());
            let _ = zw.start_file(format!("{safe_name}_issuerCertificate.crt"), opts);
            let _ = zw.write_all(issuer_cert.as_bytes());
        } else {
            let _ = zw.start_file(format!("{safe_name}.crt"), opts);
            let _ = zw.write_all(server_cert.as_bytes());
            let _ = zw.start_file(format!("{safe_name}.pem"), opts);
            let _ = zw.write_all(server_cert.as_bytes());
        }

        let _ = zw.start_file(format!("{safe_name}.key"), opts);
        let _ = zw.write_all(cert.key_pem.as_bytes());

        let domains = if cert.domains.is_empty() && !cert.domain.is_empty() {
            vec![cert.domain.clone()]
        } else {
            cert.domains.clone()
        };
        let info = serde_json::json!({
            "domain": cert.domain, "domains": domains,
            "issued_at": cert.issued_at, "expires_at": cert.expires_at,
            "source": cert.source, "name": cert.name,
        });
        let info_bytes = serde_json::to_vec_pretty(&info).unwrap_or_default();
        let _ = zw.start_file("info.json", opts);
        let _ = zw.write_all(&info_bytes);
        let _ = zw.finish();
    }
    buf.into_inner()
}

// ─── IP Filter ────────────────────────────────────────────────────────────────

pub async fn list_ipfilters(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    ok_json(serde_json::to_value(&state.data.read().await.ipfilter).unwrap_or_default())
}

pub async fn list_ipfilter_targets(State(state): State<AppState>, headers: HeaderMap) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let d = state.data.read().await;

    #[derive(serde::Serialize)]
    struct TargetItem {
        #[serde(rename = "type")]
        target_type: String,
        target_id: String,
        target_name: String,
    }
    let mut items: Vec<TargetItem> = vec![
        TargetItem {
            target_type: "admin".into(),
            target_id: "".into(),
            target_name: "管理后台（全局）".into(),
        },
        TargetItem {
            target_type: "portforward".into(),
            target_id: "".into(),
            target_name: "端口转发（全部规则）".into(),
        },
    ];
    for pf in &d.portforward {
        let name = if pf.name.is_empty() {
            format!("端口 {}", pf.effective_listen_port())
        } else {
            pf.name.clone()
        };
        items.push(TargetItem {
            target_type: "portforward".into(),
            target_id: pf.id.clone(),
            target_name: name,
        });
    }
    items.push(TargetItem {
        target_type: "webservice".into(),
        target_id: "".into(),
        target_name: "网页服务（全部路由）".into(),
    });
    for svc in &d.webservice {
        let svc_name = if svc.name.is_empty() {
            format!("服务:{}", svc.listen_port)
        } else {
            svc.name.clone()
        };
        for rt in &svc.routes {
            let rt_name = if rt.name.is_empty() {
                rt.domain.clone()
            } else {
                rt.name.clone()
            };
            items.push(TargetItem {
                target_type: "webservice".into(),
                target_id: rt.id.clone(),
                target_name: format!("{svc_name} / {rt_name}"),
            });
        }
    }
    ok_json(serde_json::to_value(&items).unwrap_or_default())
}

pub async fn create_ipfilter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<IpFilterRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    if body.scopes.is_empty() {
        return bad_request("scopes cannot be empty");
    }

    let existing = state.data.read().await.ipfilter.clone();
    if let Some(conflict) = has_scope_conflict(&existing, "", &body.scopes) {
        return bad_request(&format!("该范围已被其他规则占用: {conflict}"));
    }

    body.id = new_id();
    body.created_at = now_rfc3339();
    if body.mode != "blacklist" {
        body.mode = "whitelist".to_string();
    }

    let mut d = state.data.write().await;
    d.ipfilter.push(body.clone());
    drop(d);
    let _ = state.db.save_ip_filter(&body).await;
    (StatusCode::CREATED, Json(serde_json::to_value(&body).unwrap_or_default())).into_response()
}

pub async fn update_ipfilter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut body): Json<IpFilterRule>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    if body.scopes.is_empty() {
        return bad_request("scopes cannot be empty");
    }

    let existing = state.data.read().await.ipfilter.clone();
    if !existing.iter().any(|r| r.id == id) {
        return not_found("rule not found");
    }
    if let Some(conflict) = has_scope_conflict(&existing, &id, &body.scopes) {
        return bad_request(&format!("该范围已被其他规则占用: {conflict}"));
    }

    body.id = id.clone();
    if body.mode != "blacklist" {
        body.mode = "whitelist".to_string();
    }

    let mut d = state.data.write().await;
    if let Some(x) = d.ipfilter.iter_mut().find(|r| r.id == id) {
        body.created_at = x.created_at.clone();
        *x = body.clone();
    }
    drop(d);
    let _ = state.db.save_ip_filter(&body).await;
    state.apply_engines().await;
    ok_json(serde_json::to_value(&body).unwrap_or_default())
}

pub async fn delete_ipfilter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    d.ipfilter.retain(|x| x.id != id);
    drop(d);
    {
        let snap = state.data.read().await.ipfilter.iter().find(|x| x.id == id).cloned();
        if let Some(r) = snap { let _ = state.db.save_ip_filter(&r).await; }
    }
    state.apply_engines().await;
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn toggle_ipfilter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);
    let mut d = state.data.write().await;
    let enabled = match d.ipfilter.iter_mut().find(|x| x.id == id) {
        None => return not_found("rule not found"),
        Some(x) => {
            x.enabled = !x.enabled;
            x.enabled
        }
    };
    let rule = d.ipfilter.iter().find(|x| x.id == id).cloned();
    drop(d);
    if let Some(ref r) = rule { let _ = state.db.save_ip_filter(r).await; }
    state.apply_engines().await;
    match rule {
        Some(r) => ok_json(serde_json::to_value(&r).unwrap_or_default()),
        None => ok_json(serde_json::json!({"enabled": enabled})),
    }
}

pub async fn upload_ipfilter_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    require_auth!(&state, &headers);
    require_admin_ipfilter!(&state, &headers);

    let mut filename = String::new();
    let mut ips: Vec<String> = vec![];

    while let Ok(Some(field)) = multipart.next_field().await {
        let fn_name = field.name().unwrap_or("").to_string();
        let fn_fname = field.file_name().unwrap_or("").to_string();
        if fn_name == "file" {
            filename = fn_fname;
            if let Ok(data) = field.text().await {
                ips = parse_ip_list(&data);
            }
        }
    }

    ok_json(serde_json::json!({"name": filename, "ips": ips}))
}

fn parse_ip_list(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = vec![];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if seen.insert(line.to_string()) {
            result.push(line.to_string());
        }
    }
    result
}

fn has_scope_conflict(
    rules: &[IpFilterRule],
    exclude_id: &str,
    new_scopes: &[IpFilterScope],
) -> Option<String> {
    let mut claimed: HashMap<(String, String), bool> = HashMap::new();
    for r in rules {
        if r.id == exclude_id {
            continue;
        }
        for s in &r.scopes {
            claimed.insert((s.scope_type.clone(), s.target_id.clone()), true);
        }
    }
    for s in new_scopes {
        if claimed.contains_key(&(s.scope_type.clone(), s.target_id.clone())) {
            let label = if s.target_id.is_empty() {
                format!("{} (全局)", s.scope_type)
            } else {
                let name = if s.target_name.is_empty() {
                    s.target_id.clone()
                } else {
                    s.target_name.clone()
                };
                format!("{}: {name}", s.scope_type)
            };
            return Some(label);
        }
    }
    None
}

pub fn clean_scopes_for_deleted_target(
    rules: &mut Vec<IpFilterRule>,
    scope_type: &str,
    target_id: &str,
) {
    for rule in rules.iter_mut() {
        rule.scopes
            .retain(|s| !(s.scope_type == scope_type && s.target_id == target_id));
    }
}

// ─── Port check ───────────────────────────────────────────────────────────────

pub async fn check_port(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<serde_json::Value>,
) -> Response {
    require_auth!(&state, &headers);
    let port = v["port"].as_u64().unwrap_or(0) as u32;
    if port == 0 || port > 65535 {
        return bad_request("invalid port");
    }
    let available = is_port_available(port);
    ok_json(serde_json::json!({"port": port, "available": available}))
}

pub async fn check_port_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    require_auth!(&state, &headers);
    let port_str = q.get("port").cloned().unwrap_or_default();
    let port: u32 = match port_str.parse() {
        Ok(p) if p > 0 && p <= 65535 => p,
        _ => return bad_request("invalid port"),
    };
    let available = is_port_available(port);
    ok_json(serde_json::json!({"port": port, "available": available}))
}

// ─── Utilities ────────────────────────────────────────────────────────────────

pub fn is_port_available(port: u32) -> bool {
    if port == 0 || port > 65535 {
        return false;
    }
    std::net::TcpListener::bind(format!("0.0.0.0:{port}")).is_ok()
}

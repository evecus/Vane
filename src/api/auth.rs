use crate::api::AppState;
use crate::config::{db, types::now_rfc3339};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ─── Admin login log ──────────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct AdminLoginRecord {
    pub ip: String,
    pub success: bool,
    pub time: String,
}

static ADMIN_LOGS: Lazy<Mutex<Vec<AdminLoginRecord>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn log_admin(ip: &str, success: bool) {
    let mut logs = ADMIN_LOGS.lock().unwrap();
    logs.push(AdminLoginRecord {
        ip: ip.to_string(),
        success,
        time: now_rfc3339(),
    });
    if logs.len() > 500 {
        let len = logs.len();
        logs.drain(0..len - 500);
    }
}

pub async fn get_admin_logs(State(_): State<AppState>) -> impl IntoResponse {
    let logs = ADMIN_LOGS.lock().unwrap().clone();
    Json(logs)
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

struct LoginAttempt {
    count: u32,
    window_at: chrono::DateTime<Utc>,
}

const MAX_LOGIN_ATTEMPTS: u32 = 10;
const LOGIN_WINDOW_SECS: i64 = 600; // 10 minutes

static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, LoginAttempt>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn check_rate_limit(ip: &str) -> bool {
    let mut map = LOGIN_ATTEMPTS.lock().unwrap();
    let now = Utc::now();
    if let Some(a) = map.get_mut(ip) {
        if (now - a.window_at).num_seconds() > LOGIN_WINDOW_SECS {
            a.count = 0;
            a.window_at = now;
        }
        if a.count >= MAX_LOGIN_ATTEMPTS {
            return false;
        }
        a.count += 1;
    } else {
        map.insert(ip.to_string(), LoginAttempt { count: 1, window_at: now });
    }
    true
}

fn clear_rate_limit(ip: &str) {
    LOGIN_ATTEMPTS.lock().unwrap().remove(ip);
}

// ─── Login / Logout ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> impl IntoResponse {
    let ip = extract_client_ip(&headers);

    if !check_rate_limit(&ip) {
        log_admin(&ip, false);
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "登录尝试次数过多，请稍后再试"}))).into_response();
    }

    let ok = {
        let cfg = state.cfg.read();
        cfg.admin.username == req.username && cfg.admin.check_password(&req.password)
    };

    if !ok {
        log_admin(&ip, false);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "用户名或密码错误"}))).into_response();
    }

    clear_rate_limit(&ip);
    log_admin(&ip, true);

    let token = generate_token();
    let expires_at = (Utc::now() + chrono::Duration::hours(24)).timestamp();

    if let Some(dd) = state.cfg.read().data_dir.clone() {
        let _ = db::session_set(&dd, &token, expires_at);
    }

    Json(serde_json::json!({"token": token})).into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !token.is_empty() {
        if let Some(dd) = state.cfg.read().data_dir.clone() {
            let _ = db::session_delete(&dd, &token);
        }
    }
    Json(serde_json::json!({"ok": true}))
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    // IP filter on admin scope
    let client_ip = extract_client_ip(&headers);
    if !state.cfg.check_ip_allowed("admin", "", &client_ip) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let token = headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if token.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    let dd = state.cfg.read().data_dir.clone();
    let Some(dd) = dd else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no data dir").into_response();
    };

    let exp = match db::session_get(&dd, &token) {
        Ok(Some(e)) => e,
        _ => {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
        }
    };

    if Utc::now().timestamp() > exp {
        let _ = db::session_delete(&dd, &token);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }

    // Sliding expiry: renew by 24h
    let new_exp = (Utc::now() + chrono::Duration::hours(24)).timestamp();
    let _ = db::session_set(&dd, &token, new_exp);

    next.run(req).await
}

// ─── Safe-entry middleware (used in main for static file serving) ──────────────

pub fn check_safe_entry(path: &str, entry: &str) -> bool {
    if path.starts_with("/api/")
        || path.starts_with("/assets/")
        || matches!(path, "/favicon.svg" | "/favicon.ico" | "/favicon.png"
            | "/robots.txt" | "/manifest.json" | "/icon-192.png"
            | "/icon-512.png" | "/apple-touch-icon.png")
    {
        return true;
    }
    if entry.is_empty() {
        return true;
    }
    let prefix = format!("/{}", entry.trim_matches('/'));
    path.starts_with(&prefix)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn generate_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    // X-Real-IP from trusted proxy, or fall back to empty
    headers.get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

// ─── Purge expired sessions (called from main) ─────────────────────────────────

pub async fn purge_sessions_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        ticker.tick().await;
        if let Some(dd) = state.cfg.read().data_dir.clone() {
            let _ = db::session_purge_expired(&dd);
        }
    }
}

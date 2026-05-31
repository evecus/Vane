use crate::api::AppState;
use crate::config::{crypto, db, types::*};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::Deserialize;

pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.cfg.read();
    Json(serde_json::json!({
        "username": cfg.admin.username,
        "port": cfg.admin.port,
        "safe_entry": cfg.admin.safe_entry,
        "version": state.version,
        "welcome_shown": cfg.admin.welcome_shown,
    }))
}

pub async fn mark_welcome_shown(State(state): State<AppState>) -> impl IntoResponse {
    {
        let mut cfg = state.cfg.write();
        cfg.admin.welcome_shown = true;
    }
    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let admin = state.cfg.read().admin.clone();
        if let Err(e) = db::save_admin(&dd, &admin) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(serde_json::json!({"ok": true})).into_response()
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
    Json(req): Json<UpdateSettingsReq>,
) -> impl IntoResponse {
    let old_port;
    let old_safe_entry;

    {
        let cfg = state.cfg.read();
        old_port = cfg.admin.port;
        old_safe_entry = cfg.admin.safe_entry.clone();
    }

    // Check if credential change requires current password
    let credential_change = req.new_password.as_deref().map(|p| !p.is_empty()).unwrap_or(false)
        || req.username.as_deref().map(|u| {
            let cfg = state.cfg.read();
            !u.is_empty() && u != cfg.admin.username.as_str()
        }).unwrap_or(false);

    if credential_change {
        let current_ok = {
            let cfg = state.cfg.read();
            cfg.admin.check_password(req.current_password.as_deref().unwrap_or(""))
        };
        if !current_ok {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "当前密码错误"}))).into_response();
        }
    }

    {
        let mut cfg = state.cfg.write();
        if let Some(pw) = &req.new_password {
            if !pw.is_empty() {
                if let Err(e) = cfg.admin.set_password(pw) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
                }
            }
        }
        if let Some(u) = &req.username {
            if !u.is_empty() { cfg.admin.username = u.clone(); }
        }
        if let Some(p) = req.port {
            if p > 0 { cfg.admin.port = p; }
        }
        if let Some(se) = &req.safe_entry {
            cfg.admin.safe_entry = se.trim_matches('/').to_string();
        }
    }

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let admin = state.cfg.read().admin.clone();
        if let Err(e) = db::save_admin(&dd, &admin) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    let new_port = state.cfg.read().admin.port;
    let new_safe_entry = state.cfg.read().admin.safe_entry.clone();
    let port_changed = new_port != old_port;
    let safe_entry_changed = new_safe_entry.trim_matches('/') != old_safe_entry.trim_matches('/');
    let needs_logout = port_changed || safe_entry_changed;

    if needs_logout {
        if let Some(dd) = state.cfg.read().data_dir.clone() {
            let _ = db::session_delete_all(&dd);
        }
    }

    if port_changed {
        // Restart self after short delay
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            restart_self();
        });
    }

    Json(serde_json::json!({
        "ok": true,
        "restart": port_changed,
        "logout": needs_logout,
    })).into_response()
}

fn restart_self() {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().unwrap();
    let args: Vec<String> = std::env::args().collect();
    let err = std::process::Command::new(&exe).args(&args[1..]).exec();
    tracing::error!("restart failed: {}", err);
    std::process::exit(1);
}

// ─── Backup / Restore ─────────────────────────────────────────────────────────

pub async fn backup_config(State(state): State<AppState>) -> impl IntoResponse {
    let backup_key = crypto::portable_backup_key();
    let snap = {
        let cfg = state.cfg.read();
        FullBackup {
            version: "2".into(),
            admin: cfg.admin.clone(),
            port_forwards: cfg.port_forwards.clone(),
            ddns: cfg.ddns.clone(),
            web_services: cfg.web_services.clone(),
            tls_certs: cfg.tls_certs.clone(),
            ip_filter: cfg.ip_filter.clone(),
        }
    };

    let enc = match crypto::encrypt_json(&backup_key, &snap) {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let name = format!("backup-{}.enc", Utc::now().format("%Y%m%d-%H%M%S"));
    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let _ = db::save_backup(&dd, &name, &enc);
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}\"", name)),
        ],
        enc.into_bytes(),
    ).into_response()
}

pub async fn restore_config(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let backup_key = crypto::portable_backup_key();
    let data_str = std::str::from_utf8(&body).unwrap_or("").trim().to_string();

    let snap: FullBackup = match crypto::decrypt_json(&backup_key, &data_str) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid or unrecognised backup file: {}", e)}))).into_response(),
    };

    {
        let mut cfg = state.cfg.write();
        cfg.admin = snap.admin;
        cfg.port_forwards = snap.port_forwards;
        cfg.ddns = snap.ddns;
        cfg.web_services = snap.web_services;
        cfg.tls_certs = snap.tls_certs;
        cfg.ip_filter = snap.ip_filter;
    }

    // Persist everything
    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        let cfg = state.cfg.read();
        let _ = db::save_admin(&dd, &cfg.admin);
        for r in &cfg.port_forwards { let _ = db::save_port_forward(&dd, r); }
        for r in &cfg.ddns { let _ = db::save_ddns(&dd, r); }
        for svc in &cfg.web_services {
            let _ = db::save_web_service(&dd, svc);
            for route in &svc.routes { let _ = db::save_web_route(&dd, &svc.id, route); }
        }
        for c in &cfg.tls_certs { let _ = db::save_tls_cert(&dd, c); }
        for r in &cfg.ip_filter { let _ = db::save_ip_filter_rule(&dd, r); }
    }

    Json(serde_json::json!({"ok": true})).into_response()
}

// ─── Manifest ─────────────────────────────────────────────────────────────────

pub async fn serve_manifest(State(state): State<AppState>) -> impl IntoResponse {
    let entry = state.cfg.read().admin.safe_entry.clone();
    let start_url = if entry.is_empty() {
        "/".to_string()
    } else {
        format!("/{}/", entry.trim_matches('/'))
    };
    Json(serde_json::json!({
        "name": "Vane",
        "short_name": "Vane",
        "description": "Vane Network Manager",
        "start_url": start_url,
        "display": "standalone",
        "background_color": "#667eea",
        "theme_color": "#764ba2",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
    }))
}

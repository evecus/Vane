use crate::api::AppState;
use crate::config::types::is_port_available;
use axum::{extract::{Query, State}, response::IntoResponse, Json};
use serde::Deserialize;

pub async fn get_dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.cfg.read();
    let certs_soon = cfg.tls_certs.iter()
        .filter(|c| { let d = c.days_until_expiry(); d >= 0 && d <= 30 })
        .count();
    Json(serde_json::json!({
        "port_forwards": cfg.port_forwards.len(),
        "ddns": cfg.ddns.len(),
        "web_services": cfg.web_services.len(),
        "tls_certs": cfg.tls_certs.len(),
        "certs_expiring_soon": certs_soon,
    }))
}

#[derive(Deserialize)]
pub struct PortQuery { port: Option<String> }

pub async fn check_port(Query(q): Query<PortQuery>) -> impl IntoResponse {
    let port_str = q.port.unwrap_or_default();
    let port: u16 = match port_str.parse() {
        Ok(p) if p > 0 => p,
        _ => return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid port"}))).into_response(),
    };
    Json(serde_json::json!({
        "port": port,
        "available": is_port_available(port),
    })).into_response()
}

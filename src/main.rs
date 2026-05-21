mod acme;
mod auth;
mod db;
mod engines;
mod handlers;
mod models;
mod state;

use std::{net::SocketAddr, path::PathBuf};

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use clap::Parser;
use handlers::*;
use state::AppState;
use tokio::fs;
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser, Debug)]
struct Cli {
    /// Data directory (stores secret.key, vane.db)
    #[arg(long, default_value = "data")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.config;
    fs::create_dir_all(&root).await?;

    let state = AppState::load(root).await?;
    state.apply_engines().await;

    let port = state.config.read().await.admin.port;
    let safe_entry = state.config.read().await.admin.safe_entry.clone();

    let entry_path = if safe_entry.is_empty() {
        String::new()
    } else {
        format!("/{}", safe_entry.trim_matches('/'))
    };
    println!("\n  ✨ Vane Dashboard : http://0.0.0.0:{port}{entry_path}\n");

    let app = Router::new()
        // Auth
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        // Manifest
        .route("/manifest.json", get(serve_manifest))
        // Dashboard
        .route("/api/dashboard", get(get_dashboard))
        .route(
            "/api/admin/logs",
            get(get_admin_logs).post(append_admin_log),
        )
        .route("/api/admin/logs/query", get(query_admin_logs))
        // Sessions
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/:token", delete(revoke_session))
        // Settings
        .route("/api/settings", get(get_settings).put(update_settings))
        .route("/api/settings/welcome-shown", post(mark_welcome_shown))
        .route("/api/settings/backup", get(backup_settings))
        .route("/api/settings/restore", post(restore_settings))
        // Port check
        .route("/api/check-port", get(check_port_query).post(check_port))
        // Port Forward
        .route(
            "/api/portforward",
            get(list_port_forwards).post(create_port_forward),
        )
        .route(
            "/api/portforward/:id",
            put(update_port_forward).delete(delete_port_forward),
        )
        .route("/api/portforward/:id/toggle", post(toggle_port_forward))
        .route("/api/portforward/:id/stats", get(get_port_forward_stats))
        // DDNS
        .route("/api/ddns", get(list_ddns).post(create_ddns))
        .route("/api/ddns/interfaces", get(list_interfaces))
        .route("/api/ddns/iface-ips", get(list_iface_ips))
        .route("/api/ddns/:id", put(update_ddns).delete(delete_ddns))
        .route("/api/ddns/:id/toggle", post(toggle_ddns))
        .route("/api/ddns/:id/refresh", post(update_ddns_refresh_now))
        // Web Service
        .route(
            "/api/webservice",
            get(list_webservices).post(create_webservice),
        )
        .route("/api/webservice/logs", get(get_all_access_logs))
        .route("/api/webservice/logs/query", get(query_access_logs))
        .route("/api/webservice/logs/append", post(append_access_log))
        .route(
            "/api/webservice/:id",
            put(update_webservice).delete(delete_webservice),
        )
        .route("/api/webservice/:id/toggle", post(toggle_webservice))
        .route(
            "/api/webservice/:id/routes",
            get(list_routes).post(create_route),
        )
        .route(
            "/api/webservice/:id/routes/:rid",
            put(update_route).delete(delete_route),
        )
        .route("/api/webservice/:id/routes/:rid/toggle", post(toggle_route))
        .route("/api/webservice/:id/logs", get(get_access_logs))
        .route("/api/webservice/:id/logs/clear", post(clear_access_logs))
        // TLS
        .route("/api/tls", get(list_tls).post(create_tls))
        .route("/api/tls/upload", post(upload_tls))
        .route("/api/tls/:id", put(update_tls).delete(delete_tls))
        .route("/api/tls/:id/toggle", post(toggle_tls))
        .route("/api/tls/:id/issue", post(issue_tls))
        .route("/api/tls/:id/renew", post(renew_tls))
        .route("/api/tls/:id/download", get(download_tls))
        .route("/api/tls/:id/pem", get(get_tls_pem))
        // IP Filter
        .route("/api/ipfilter", get(list_ipfilters).post(create_ipfilter))
        .route("/api/ipfilter/targets", get(list_ipfilter_targets))
        .route("/api/ipfilter/upload", post(upload_ipfilter_file))
        .route(
            "/api/ipfilter/:id",
            put(update_ipfilter).delete(delete_ipfilter),
        )
        .route("/api/ipfilter/:id/toggle", post(toggle_ipfilter))
        // SPA fallback
        .fallback(spa_fallback)
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

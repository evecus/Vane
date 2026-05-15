mod auth;
mod engines;
mod handlers;
mod models;
mod state;

use std::{net::SocketAddr, path::PathBuf};

use axum::{
    routing::{get, post, put},
    Router,
};
use clap::Parser;
use handlers::*;
use state::AppState;
use tokio::fs;
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.config.unwrap_or_else(|| PathBuf::from("data"));
    fs::create_dir_all(&root).await?;

    let state = AppState::load(root).await?;
    state.apply_engines().await;

    let port = state.config.read().await.admin.port;

    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/dashboard", get(get_dashboard))
        .route("/api/settings", get(get_settings).put(update_settings))
        .route("/api/settings/backup", get(backup_settings))
        .route("/api/settings/restore", post(restore_settings))
        .route(
            "/api/portforward",
            get(list_port_forwards).post(create_port_forward),
        )
        .route(
            "/api/portforward/:id",
            put(update_port_forward).delete(delete_port_forward),
        )
        .route("/api/ddns", get(list_ddns).post(create_ddns))
        .route("/api/ddns/:id", put(update_ddns).delete(delete_ddns))
        .route(
            "/api/webservice",
            get(list_webservices).post(create_webservice),
        )
        .route(
            "/api/webservice/:id",
            put(update_webservice).delete(delete_webservice),
        )
        .route("/api/tls", get(list_tls).post(create_tls))
        .route("/api/tls/:id", put(update_tls).delete(delete_tls))
        .route("/api/ipfilter", get(list_ipfilters).post(create_ipfilter))
        .route(
            "/api/ipfilter/:id",
            put(update_ipfilter).delete(delete_ipfilter),
        )
        .fallback(spa_fallback)
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("✨ Dashboard: http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

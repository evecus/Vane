pub mod auth;
pub mod dashboard;
pub mod ddns;
pub mod ipfilter;
pub mod portforward;
pub mod settings;
pub mod tls;
pub mod webservice;

use crate::config::Config;
use crate::module::{
    ddns::Manager as DdnsManager, portforward::Manager as PfManager, tls::Manager as TlsManager,
    webservice::Manager as WsManager,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

// ─── App state (injected into every handler via axum::extract::State) ─────────

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,
    pub pf: Arc<PfManager>,
    pub ddns: Arc<DdnsManager>,
    pub ws: Arc<WsManager>,
    pub tls: Arc<TlsManager>,
    pub version: &'static str,
}

// ─── Router builder ───────────────────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .allow_origin(Any);

    // Public API routes
    let public = Router::new()
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout));

    // Protected API routes (require Authorization header)
    let protected = Router::new()
        // Dashboard
        .route("/api/dashboard", get(dashboard::get_dashboard))
        .route("/api/admin/logs", get(auth::get_admin_logs))
        // Settings
        .route("/api/settings", get(settings::get_settings))
        .route("/api/settings", put(settings::update_settings))
        .route(
            "/api/settings/welcome-shown",
            post(settings::mark_welcome_shown),
        )
        .route("/api/settings/backup", get(settings::backup_config))
        .route("/api/settings/restore", post(settings::restore_config))
        // Port Forward
        .route("/api/portforward", get(portforward::list))
        .route("/api/portforward", post(portforward::create))
        .route("/api/portforward/:id", put(portforward::update))
        .route("/api/portforward/:id", delete(portforward::delete_pf))
        .route("/api/portforward/:id/toggle", post(portforward::toggle))
        .route("/api/portforward/:id/stats", get(portforward::stats))
        // DDNS
        .route("/api/ddns", get(ddns::list))
        .route("/api/ddns", post(ddns::create))
        .route("/api/ddns/interfaces", get(ddns::list_interfaces))
        .route("/api/ddns/iface-ips", get(ddns::list_iface_ips))
        .route("/api/ddns/:id", put(ddns::update))
        .route("/api/ddns/:id", delete(ddns::delete_ddns))
        .route("/api/ddns/:id/toggle", post(ddns::toggle))
        .route("/api/ddns/:id/refresh", post(ddns::refresh))
        // WebService
        .route("/api/webservice", get(webservice::list_services))
        .route("/api/webservice", post(webservice::create_service))
        .route("/api/webservice/logs", get(webservice::get_all_logs))
        .route("/api/webservice/:id", put(webservice::update_service))
        .route("/api/webservice/:id", delete(webservice::delete_service))
        .route(
            "/api/webservice/:id/toggle",
            post(webservice::toggle_service),
        )
        .route("/api/webservice/:id/routes", get(webservice::list_routes))
        .route("/api/webservice/:id/routes", post(webservice::create_route))
        .route(
            "/api/webservice/:id/routes/:rid",
            put(webservice::update_route),
        )
        .route(
            "/api/webservice/:id/routes/:rid",
            delete(webservice::delete_route),
        )
        .route(
            "/api/webservice/:id/routes/:rid/toggle",
            post(webservice::toggle_route),
        )
        .route("/api/webservice/:id/logs", get(webservice::get_logs))
        // Port check
        .route("/api/check-port", get(dashboard::check_port))
        // TLS
        .route("/api/tls", get(tls::list_certs))
        .route("/api/tls", post(tls::create_cert))
        .route("/api/tls/upload", post(tls::upload_cert))
        .route("/api/tls/:id", put(tls::update_cert))
        .route("/api/tls/:id", delete(tls::delete_cert))
        .route("/api/tls/:id/issue", post(tls::issue_cert))
        .route("/api/tls/:id/download", get(tls::download_cert))
        .route("/api/tls/:id/pem", get(tls::get_cert_pem))
        // IP Filter
        .route("/api/ipfilter", get(ipfilter::list_rules))
        .route("/api/ipfilter", post(ipfilter::create_rule))
        .route("/api/ipfilter/targets", get(ipfilter::list_targets))
        .route("/api/ipfilter/upload", post(ipfilter::upload_file))
        .route("/api/ipfilter/:id", put(ipfilter::update_rule))
        .route("/api/ipfilter/:id", delete(ipfilter::delete_rule))
        .route("/api/ipfilter/:id/toggle", post(ipfilter::toggle_rule))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    // Dynamic manifest.json
    let manifest = Router::new().route("/manifest.json", get(settings::serve_manifest));

    Router::new()
        .merge(public)
        .merge(protected)
        .merge(manifest)
        .layer(cors)
        .with_state(state)
}

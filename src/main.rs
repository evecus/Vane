mod api;
mod assets;
mod config;
mod module;

use api::{auth::check_safe_entry, AppState};
use assets::serve_asset;
use axum::{extract::Request, http::StatusCode, response::IntoResponse, Router};
use config::DataDir;
use std::sync::Arc;
use tracing::info;

// ─── Version (injected by build.rs or cargo) ─────────────────────────────────

pub static VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23+ 需要在进程级别显式安装加密后端，否则所有 TLS 操作（ACME、
    // HTTPS 客户端、反向代理 TLS 握手）会在运行时 panic。
    // 必须在任何 rustls/reqwest/instant-acme/tokio-rustls 调用前执行。
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vane=info,tower_http=warn".into()),
        )
        .init();

    // CLI args
    let mut config_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            config_path = args.next();
        } else if let Some(path) = arg.strip_prefix("--config=") {
            config_path = Some(path.to_string());
        }
    }

    // ── 1. Init data dir + config ─────────────────────────────────────────
    let dd = DataDir::open(config_path.as_deref())?;
    let cfg = config::load(Arc::clone(&dd))?;

    print_banner(&cfg);

    // ── 2. Start modules ──────────────────────────────────────────────────
    let pf = module::portforward::Manager::new(cfg.clone());
    let ddns = module::ddns::Manager::new(cfg.clone());
    let ws = module::webservice::Manager::new(cfg.clone());
    let tls = module::tls::Manager::new(cfg.clone());

    pf.start_all();
    ddns.start_all();
    ws.start_all();
    tls.start_auto_renew();

    // ── 3. Build HTTP router ──────────────────────────────────────────────
    let state = AppState {
        cfg: cfg.clone(),
        pf: Arc::clone(&pf),
        ddns: Arc::clone(&ddns),
        ws: Arc::clone(&ws),
        tls: Arc::clone(&tls),
        version: VERSION,
    };

    // Spawn session purge task
    let state_clone = state.clone();
    tokio::spawn(async move {
        api::auth::purge_sessions_loop(state_clone).await;
    });

    // Spawn rate-limit map GC task (prevents unbounded memory growth under scan attacks)
    tokio::spawn(api::auth::purge_rate_limit_loop());

    // Spawn log persistence task: flush every 30 minutes, keep latest 2000 rows per log type.
    {
        let ws_clone = Arc::clone(&ws);
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            const FLUSH_INTERVAL_SECS: u64 = 30 * 60;
            const ACCESS_LOG_KEEP: usize = 2000;
            const ADMIN_LOG_KEEP: usize = 200;

            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS));
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                ws_clone.flush_logs_to_db(ACCESS_LOG_KEEP);
                if let Some(dd) = cfg_clone.read().data_dir.clone() {
                    api::auth::flush_admin_logs_to_db(&dd, ADMIN_LOG_KEEP);
                }
            }
        });
    }

    let api_router = api::build_router(state.clone());

    // Static file handler with safe-entry and SPA fallback
    let static_handler = Router::new().fallback(move |req: Request| {
        let cfg = state.cfg.clone();
        async move {
            let path = req.uri().path().to_string();
            let entry = cfg.read().admin.safe_entry.clone();

            // Enforce safe-entry gate
            if !check_safe_entry(&path, &entry) {
                return StatusCode::FORBIDDEN.into_response();
            }

            serve_asset(
                req.uri().clone(),
                if entry.is_empty() { None } else { Some(entry) },
            )
            .await
            .into_response()
        }
    });

    let app = Router::new().merge(api_router).merge(static_handler);

    let port = cfg.read().admin.port;
    let addr = format!("0.0.0.0:{}", port);
    info!("Vane {} → http://{}", VERSION, addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn print_banner(cfg: &config::Config) {
    let inner = cfg.read();
    let entry = if inner.admin.safe_entry.is_empty() {
        String::new()
    } else {
        format!("/{}", inner.admin.safe_entry)
    };
    println!(
        "\n  ✨ Dashboard : http://0.0.0.0:{}{}\n     User      : {}\n     Version   : {}\n",
        inner.admin.port, entry, inner.admin.username, VERSION
    );
}

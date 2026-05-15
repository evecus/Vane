use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use axum::{extract::State, http::{HeaderMap, StatusCode, Uri}, response::{Html, IntoResponse, Response}, routing::{get, post, put}, Json, Router};
use chrono::Utc;
use clap::Parser;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::Pbkdf2;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::RwLock};
use tower_http::cors::{Any, CorsLayer};

#[derive(Parser, Debug)]
struct Cli { #[arg(long)] config: Option<PathBuf> }

#[derive(Clone)]
struct AppState { cfg: Arc<RwLock<Config>>, sessions: Arc<RwLock<HashMap<String,String>>>, root: PathBuf }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config { admin: AdminConfig }
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminConfig { username: String, password_hash: String, port: u16, safe_entry: String }

impl Default for Config { fn default() -> Self { Self { admin: AdminConfig { username:"admin".into(), password_hash: hash_password("vane1234").unwrap(), port:4455, safe_entry:String::new() } } } }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = cli.config.unwrap_or_else(|| PathBuf::from("data"));
    fs::create_dir_all(&root).await?;
    let cfg_path = root.join("vane.json");
    let cfg: Config = match fs::read_to_string(&cfg_path).await { Ok(s)=>serde_json::from_str(&s).context("parse vane.json")?, Err(_)=>{let d=Config::default();fs::write(&cfg_path, serde_json::to_vec_pretty(&d)?).await?;d} };

    let state = AppState { cfg: Arc::new(RwLock::new(cfg)), sessions: Arc::new(RwLock::new(HashMap::new())), root };
    let app = Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/dashboard", get(dashboard))
        .route("/api/settings", get(get_settings).put(update_settings))
        .fallback(spa_fallback)
        .with_state(state.clone())
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any));

    let port = state.cfg.read().await.admin.port;
    let addr = SocketAddr::from(([0,0,0,0], port));
    println!("✨ Dashboard: http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)] struct LoginReq { username:String, password:String }
#[derive(Serialize)] struct TokenResp { token:String }

async fn login(State(state): State<AppState>, Json(req): Json<LoginReq>) -> Response {
    let cfg = state.cfg.read().await;
    if req.username != cfg.admin.username || !verify_password(&req.password, &cfg.admin.password_hash) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"用户名或密码错误"}))).into_response();
    }
    drop(cfg);
    let token = format!("{}-{}", req.username, Utc::now().timestamp_nanos_opt().unwrap_or_default());
    state.sessions.write().await.insert(token.clone(), req.username);
    (StatusCode::OK, Json(TokenResp{token})).into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = bearer(&headers) { state.sessions.write().await.remove(&t); }
    (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await { return StatusCode::UNAUTHORIZED.into_response(); }
    (StatusCode::OK, Json(serde_json::json!({"version":"rust-rewrite","status":"running"}))).into_response()
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !authorized(&state, &headers).await { return StatusCode::UNAUTHORIZED.into_response(); }
    let cfg = state.cfg.read().await.clone();
    (StatusCode::OK, Json(cfg)).into_response()
}

async fn update_settings(State(state): State<AppState>, headers: HeaderMap, Json(new_cfg): Json<Config>) -> Response {
    if !authorized(&state, &headers).await { return StatusCode::UNAUTHORIZED.into_response(); }
    {
        let mut cfg = state.cfg.write().await;
        *cfg = new_cfg.clone();
    }
    let path = state.root.join("vane.json");
    match fs::write(path, serde_json::to_vec_pretty(&new_cfg).unwrap()).await { Ok(_) => (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response(), Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response() }
}

async fn spa_fallback(State(state): State<AppState>, uri: Uri) -> Response {
    let safe = state.cfg.read().await.admin.safe_entry.clone();
    let mut p = uri.path().to_string();
    if !safe.is_empty() {
        let prefix = format!("/{}", safe.trim_matches('/'));
        if p.starts_with(&prefix) { p = p[prefix.len()..].to_string(); }
    }
    let rel = if p == "/" { "index.html".into() } else { p.trim_start_matches('/').into() };
    let dist = PathBuf::from("web/dist").join(&rel);
    let bytes = fs::read(&dist).await.or_else(|_| async { fs::read("web/dist/index.html").await }).await;
    match bytes { Ok(b)=>Html(String::from_utf8_lossy(&b).to_string()).into_response(), Err(_)=>(StatusCode::NOT_FOUND,"not found").into_response() }
}

async fn authorized(state:&AppState, headers:&HeaderMap)->bool{ bearer(headers).map(|t| state.sessions.blocking_read().contains_key(&t)).unwrap_or(false) }
fn bearer(headers:&HeaderMap)->Option<String>{ headers.get("authorization").and_then(|v|v.to_str().ok()).and_then(|v|v.strip_prefix("Bearer ")).map(|s|s.to_string()) }
fn hash_password(p:&str)->anyhow::Result<String>{ let salt=SaltString::generate(&mut OsRng); Ok(Pbkdf2.hash_password(p.as_bytes(), &salt)?.to_string()) }
fn verify_password(p:&str,h:&str)->bool{ PasswordHash::new(h).ok().and_then(|ph|Pbkdf2.verify_password(p.as_bytes(),&ph).ok()).is_some() }

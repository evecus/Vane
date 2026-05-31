use axum::{
    body::Body,
    http::{header, Response, StatusCode, Uri},
    response::IntoResponse,
};
use rust_embed::RustEmbed;

/// Embeds everything under web/dist/ at compile time.
/// If the directory doesn't exist (e.g. CI without frontend build),
/// the binary still compiles but returns 404 for asset requests.
#[derive(RustEmbed)]
#[folder = "web/dist/"]
#[include = "*"]
pub struct WebAssets;

pub async fn serve_asset(uri: Uri, safe_entry: Option<String>) -> impl IntoResponse {
    let path = uri.path();
    let mut asset_path = path.trim_start_matches('/').to_string();

    // Strip safe_entry prefix if configured
    if let Some(entry) = safe_entry {
        if !entry.is_empty() {
            let prefix = format!("{}/", entry.trim_matches('/'));
            if let Some(stripped) = asset_path.strip_prefix(&prefix) {
                asset_path = stripped.to_string();
            } else if asset_path == entry.trim_matches('/') {
                asset_path = String::new();
            }
        }
    }

    if asset_path.is_empty() {
        asset_path = "index.html".to_string();
    }

    match WebAssets::get(&asset_path) {
        Some(content) => {
            let mime = mime_guess::from_path(&asset_path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .body(Body::from(content.data.into_owned()))
                .unwrap()
        }
        None => {
            // SPA fallback: return index.html for client-side routing
            match WebAssets::get("index.html") {
                Some(content) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(content.data.into_owned()))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("index.html not found"))
                    .unwrap(),
            }
        }
    }
}

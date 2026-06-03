use crate::api::AppState;
use crate::config::{db, types::*};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::io::Write;

pub async fn list_certs(State(state): State<AppState>) -> impl IntoResponse {
    // Strip key_pem from response (never send private key in list).
    // Also inject `days_left` (computed from expires_at) and `domain`
    // (first entry of domains[] for display) so the dashboard can use them directly.
    let certs: Vec<serde_json::Value> = state.cfg.read().tls_certs.iter().map(|c| {
        let mut v = serde_json::to_value(c).unwrap();
        if let Some(m) = v.as_object_mut() {
            m.remove("key_pem");
            // Inject computed days_left
            m.insert("days_left".into(), serde_json::json!(c.days_until_expiry()));
            // Ensure a flat `domain` field for the dashboard card
            // (prefer first entry of domains[], fall back to stored domain field)
            let display_domain = c.domains.first().cloned()
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| c.domain.clone());
            m.insert("domain".into(), serde_json::json!(display_domain));
        }
        v
    }).collect();
    Json(certs)
}

#[derive(Deserialize)]
pub struct CertReq {
    name: Option<String>,
    domains: Option<Vec<String>>,
    domain: Option<String>,
    source: Option<String>,
    ca_provider: Option<String>,
    provider: Option<String>,
    provider_conf: Option<ProviderConf>,
    auto_renew: Option<bool>,
    email: Option<String>,
}

pub async fn create_cert(State(state): State<AppState>, Json(req): Json<CertReq>) -> impl IntoResponse {
    let domains = req.domains.unwrap_or_default();
    let domain = req.domain.unwrap_or_else(|| domains.first().cloned().unwrap_or_default());
    let cert = TlsCert {
        id: new_id(),
        name: req.name.unwrap_or_default(),
        domains,
        domain,
        source: req.source.unwrap_or_else(|| "acme".into()),
        ca_provider: req.ca_provider.unwrap_or_else(|| "letsencrypt".into()),
        provider: req.provider.unwrap_or_default(),
        provider_conf: req.provider_conf.unwrap_or_default(),
        cert_pem: String::new(),
        key_pem: String::new(),
        issued_at: String::new(),
        expires_at: String::new(),
        auto_renew: req.auto_renew.unwrap_or(false),
        email: req.email.unwrap_or_default(),
        status: "pending".into(),
        error_msg: String::new(),
        created_at: now_rfc3339(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_tls_cert(&dd, &cert) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    state.cfg.write().tls_certs.push(cert.clone());
    (StatusCode::CREATED, Json(cert)).into_response()
}

pub async fn update_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CertReq>,
) -> impl IntoResponse {
    {
        let mut cfg = state.cfg.write();
        let Some(c) = cfg.tls_certs.iter_mut().find(|c| c.id == id) else {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
        };
        if let Some(v) = req.name { c.name = v; }
        if let Some(v) = req.domains { c.domains = v; }
        if let Some(v) = req.domain { c.domain = v; }
        if let Some(v) = req.source { c.source = v; }
        if let Some(v) = req.ca_provider { c.ca_provider = v; }
        if let Some(v) = req.provider { c.provider = v; }
        if let Some(v) = req.provider_conf { c.provider_conf = v; }
        if let Some(v) = req.auto_renew { c.auto_renew = v; }
        if let Some(v) = req.email { c.email = v; }
    }

    let cert = state.cfg.read().tls_certs.iter().find(|c| c.id == id).cloned();
    let Some(cert) = cert else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_tls_cert(&dd, &cert) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    Json(cert).into_response()
}

pub async fn delete_cert(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    state.cfg.write().tls_certs.retain(|c| c.id != id);

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::delete_tls_cert(&dd, &id) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }

    // Re-match all routes after cert removal
    state.ws.rematch_all_routes();
    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn issue_cert(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let tls = state.tls.clone();
    tokio::spawn(async move { let _ = tls.issue_cert(&id).await; });
    Json(serde_json::json!({"ok": true, "message": "证书申请已开始，请稍后刷新查看状态"}))
}

pub async fn upload_cert(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    // Expect JSON body with cert_pem and key_pem
    #[derive(Deserialize)]
    struct UploadReq {
        name: Option<String>,
        cert_pem: String,
        key_pem: String,
        auto_renew: Option<bool>,
    }

    let req: UploadReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    // Validate key pair
    if let Err(e) = validate_pem_pair(&req.cert_pem, &req.key_pem) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid cert/key: {}", e)}))).into_response();
    }

    let domains = crate::module::tls::extract_domains_from_cert_pem(&req.cert_pem);
    let domain = domains.first().cloned().unwrap_or_default();
    let expires_at = parse_cert_expiry(&req.cert_pem).unwrap_or_default();

    let cert = TlsCert {
        id: new_id(),
        name: req.name.unwrap_or_else(|| domain.clone()),
        domains: domains.clone(),
        domain,
        source: "upload".into(),
        ca_provider: String::new(),
        provider: String::new(),
        provider_conf: ProviderConf::default(),
        cert_pem: req.cert_pem,
        key_pem: req.key_pem,
        issued_at: now_rfc3339(),
        expires_at,
        auto_renew: req.auto_renew.unwrap_or(false),
        email: String::new(),
        status: "active".into(),
        error_msg: String::new(),
        created_at: now_rfc3339(),
    };

    let dd = state.cfg.read().data_dir.clone();
    if let Some(dd) = dd {
        if let Err(e) = db::save_tls_cert(&dd, &cert) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
        }
    }
    state.cfg.write().tls_certs.push(cert.clone());
    state.ws.rematch_all_routes();
    (StatusCode::CREATED, Json(cert)).into_response()
}

pub async fn download_cert(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let cert = state.cfg.read().tls_certs.iter().find(|c| c.id == id).cloned();
    let Some(cert) = cert else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    if cert.cert_pem.is_empty() || cert.key_pem.is_empty() {
        return (StatusCode::BAD_REQUEST, "证书尚未签发，无法下载").into_response();
    }

    // Split cert chain: first PEM block = server cert, rest = intermediate/issuer
    let (server_cert, issuer_cert) = split_cert_chain(&cert.cert_pem);
    let (server_cert, issuer_cert) = if server_cert.is_empty() {
        (cert.cert_pem.clone(), String::new())
    } else {
        (server_cert, issuer_cert)
    };

    let safe_name = sanitize_filename(if cert.domain.is_empty() { "cert" } else { &cert.domain });
    let safe_name = if safe_name.is_empty() { "cert".to_string() } else { safe_name };

    // Build zip in memory
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        use zip::write::SimpleFileOptions;
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        let fullchain = if issuer_cert.is_empty() {
            server_cert.clone()
        } else {
            format!("{}{}", server_cert, issuer_cert)
        };

        // .crt and .pem = fullchain (server cert + intermediate)
        let _ = zw.start_file(format!("{}.crt", safe_name), opts);
        let _ = zw.write_all(fullchain.as_bytes());
        let _ = zw.start_file(format!("{}.pem", safe_name), opts);
        let _ = zw.write_all(fullchain.as_bytes());

        if !issuer_cert.is_empty() {
            let _ = zw.start_file(format!("{}_issuerCertificate.crt", safe_name), opts);
            let _ = zw.write_all(issuer_cert.as_bytes());
        }

        // Private key
        let _ = zw.start_file(format!("{}.key", safe_name), opts);
        let _ = zw.write_all(cert.key_pem.as_bytes());

        // info.json with metadata
        let domains = if cert.domains.is_empty() && !cert.domain.is_empty() {
            vec![cert.domain.clone()]
        } else {
            cert.domains.clone()
        };
        let info = serde_json::json!({
            "domain":     cert.domain,
            "domains":    domains,
            "issued_at":  cert.issued_at,
            "expires_at": cert.expires_at,
            "source":     cert.source,
            "name":       cert.name,
        });
        let info_bytes = serde_json::to_vec_pretty(&info).unwrap_or_default();
        let _ = zw.start_file("info.json", opts);
        let _ = zw.write_all(&info_bytes);

        let _ = zw.finish();
    }

    let zip_bytes = buf.into_inner();
    let filename = format!("{}-certs.zip", safe_name);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename)),
        ],
        zip_bytes,
    ).into_response()
}

pub async fn get_cert_pem(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let cert = state.cfg.read().tls_certs.iter().find(|c| c.id == id).cloned();
    let Some(cert) = cert else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response();
    };
    Json(serde_json::json!({
        "cert_pem": cert.cert_pem,
        "key_pem": cert.key_pem,
    })).into_response()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn validate_pem_pair(cert_pem: &str, key_pem: &str) -> anyhow::Result<()> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;
    let certs: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() { anyhow::bail!("no certificate in PEM"); }
    let _key = private_key(&mut BufReader::new(key_pem.as_bytes()))?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    Ok(())
}

fn parse_cert_expiry(cert_pem: &str) -> Option<String> {
    crate::module::tls::parse_cert_expiry(cert_pem)
}

fn sanitize_filename(s: &str) -> String {
    s.chars().map(|c| match c {
        '*' => '_',
        '"' | '\r' | '\n' | '\\' | '/' | ':' | '?' | '<' | '>' | '|' => '_',
        _ => c,
    }).collect()
}

/// Split a PEM certificate chain into the server cert (first block)
/// and the issuer/intermediate certs (remaining blocks).
fn split_cert_chain(pem_chain: &str) -> (String, String) {
    let mut server = String::new();
    let mut issuer = String::new();
    let mut current = String::new();
    let mut first = true;

    for line in pem_chain.lines() {
        current.push_str(line);
        current.push('\n');
        if line.starts_with("-----END ") {
            if first {
                server = current.clone();
                first = false;
            } else {
                issuer.push_str(&current);
            }
            current.clear();
        }
    }

    (server, issuer)
}

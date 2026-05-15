use axum::http::HeaderMap;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::Pbkdf2;
use rand_core::OsRng;

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

pub fn hash_password(p: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Pbkdf2
        .hash_password(p.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hash failed: {e}"))
}

pub fn verify_password(p: &str, h: &str) -> bool {
    PasswordHash::new(h)
        .ok()
        .and_then(|ph| Pbkdf2.verify_password(p.as_bytes(), &ph).ok())
        .is_some()
}

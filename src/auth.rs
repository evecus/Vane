use axum::http::HeaderMap;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use pbkdf2::Pbkdf2;
use rand_core::OsRng;

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // Support both "Bearer <token>" and raw token
            if let Some(s) = v.strip_prefix("Bearer ") {
                Some(s.to_string())
            } else {
                Some(v.to_string())
            }
        })
}

pub fn hash_password(p: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Pbkdf2
        .hash_password(p.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hash failed: {e}"))
}

pub fn verify_password(p: &str, h: &str) -> bool {
    // Support bcrypt hashes (from Go version) and pbkdf2 hashes (Rust version)
    if h.starts_with("$2") {
        return bcrypt::verify(p, h).unwrap_or(false);
    }
    PasswordHash::new(h)
        .ok()
        .and_then(|ph| Pbkdf2.verify_password(p.as_bytes(), &ph).ok())
        .is_some()
}

/// Generate a cryptographically random token (32 bytes hex)
pub fn generate_token() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// bcrypt hash for route passwords (compatible with Go's bcrypt)
pub fn bcrypt_hash(password: &str) -> anyhow::Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow::anyhow!("bcrypt hash failed: {e}"))
}

/// Verify bcrypt hash (for route auth_pass_hash)
pub fn bcrypt_verify(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

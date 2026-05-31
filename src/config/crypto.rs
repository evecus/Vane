use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

const KDF_SALT: &[u8] = b"vane-kdf-v1";
const KDF_ITER: u32 = 100_000;

/// Derive a 32-byte AES key from a passphrase using PBKDF2-SHA256.
/// Fixed salt = portability; the key file itself is the secret.
pub fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), KDF_SALT, KDF_ITER, &mut key);
    key
}

/// Encrypt `data` with AES-256-GCM. Returns hex-encoded nonce||ciphertext.
pub fn encrypt_bytes(key: &[u8; 32], data: &[u8]) -> Result<String> {
    use aes_gcm::aead::rand_core::RngCore;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("{}", e))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("encrypt: {}", e))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(hex::encode(out))
}

/// Decrypt hex-encoded nonce||ciphertext. Returns plaintext bytes.
pub fn decrypt_bytes(key: &[u8; 32], hex_ct: &str) -> Result<Vec<u8>> {
    let ct = hex::decode(hex_ct).map_err(|e| anyhow!("hex decode: {}", e))?;
    if ct.len() < 12 {
        return Err(anyhow!("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("{}", e))?;
    let nonce = Nonce::from_slice(&ct[..12]);
    cipher
        .decrypt(nonce, &ct[12..])
        .map_err(|e| anyhow!("decrypt: {}", e))
}

/// Encrypt a value to JSON, then AES-256-GCM.
pub fn encrypt_json<T: serde::Serialize>(key: &[u8; 32], v: &T) -> Result<String> {
    let json = serde_json::to_vec(v)?;
    encrypt_bytes(key, &json)
}

/// Decrypt and deserialize from JSON.
pub fn decrypt_json<T: serde::de::DeserializeOwned>(key: &[u8; 32], hex_ct: &str) -> Result<T> {
    let plain = decrypt_bytes(key, hex_ct)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Encrypt a plain string.
pub fn encrypt_str(key: &[u8; 32], s: &str) -> Result<String> {
    encrypt_json(key, &s)
}

/// Decrypt to a plain string.
pub fn decrypt_str(key: &[u8; 32], hex_ct: &str) -> Result<String> {
    decrypt_json(key, hex_ct)
}

/// Portable backup key — fixed passphrase so backups are cross-machine.
pub fn portable_backup_key() -> [u8; 32] {
    derive_key("vane-portable-backup-v1")
}

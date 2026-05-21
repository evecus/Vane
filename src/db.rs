/// Database layer: SQLite storage with AES-256-GCM encryption.
///
/// Design mirrors the Go version (config/config.go):
///   - A 32-byte key is loaded from `data/secret.key` (or env VANE_SECRET).
///   - Sensitive fields (IPs, API keys, PEM certs, …) are stored as AES-GCM
///     ciphertext encoded as hex strings.
///   - Non-sensitive metadata (IDs, names, ports, timestamps) is stored in the
///     clear so the DB is still queryable without decryption.
use std::{path::Path, sync::Arc};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;

use crate::models::*;

// ─── Encryption ───────────────────────────────────────────────────────────────

const KEY_ENV: &str = "VANE_SECRET";
const KDF_SALT: &[u8] = b"vane-kdf-v1";
const KDF_ITER: u32 = 100_000;

/// Derive a 32-byte AES key from a passphrase using PBKDF2-SHA256.
fn derive_key(passphrase: &str) -> [u8; 32] {
    use sha2::Sha256;
    pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), KDF_SALT, KDF_ITER)
}

/// Encrypt `plaintext` with AES-256-GCM, return nonce‖ciphertext as hex.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ct);
    Ok(hex::encode(combined))
}

/// Decrypt hex-encoded nonce‖ciphertext produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], hex_ct: &str) -> anyhow::Result<Vec<u8>> {
    if hex_ct.is_empty() {
        return Ok(vec![]);
    }
    let raw = hex::decode(hex_ct).context("hex decode")?;
    if raw.len() < 12 {
        bail!("ciphertext too short");
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))
}

/// Encrypt a JSON-serialisable value.
pub fn encrypt_json<T: serde::Serialize>(key: &[u8; 32], v: &T) -> anyhow::Result<String> {
    let plain = serde_json::to_vec(v)?;
    encrypt(key, &plain)
}

/// Decrypt and deserialise a JSON value.
pub fn decrypt_json<T: serde::de::DeserializeOwned>(
    key: &[u8; 32],
    hex_ct: &str,
) -> anyhow::Result<T> {
    let plain = decrypt(key, hex_ct)?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Encrypt a plain string.
pub fn encrypt_str(key: &[u8; 32], s: &str) -> anyhow::Result<String> {
    encrypt(key, s.as_bytes())
}

/// Decrypt a plain string.
pub fn decrypt_str(key: &[u8; 32], hex_ct: &str) -> anyhow::Result<String> {
    if hex_ct.is_empty() {
        return Ok(String::new());
    }
    let plain = decrypt(key, hex_ct)?;
    Ok(String::from_utf8(plain)?)
}

// ─── Portable backup key ──────────────────────────────────────────────────────

/// Fixed key used for portable backups (same passphrase as Go version so backup
/// files are cross-compatible).
fn portable_backup_key() -> [u8; 32] {
    derive_key("vane-portable-backup-v1")
}

// ─── Database ─────────────────────────────────────────────────────────────────

/// Thread-safe SQLite handle with encryption key.
#[derive(Clone)]
pub struct Db {
    pub key: Arc<[u8; 32]>,
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open (or create) the database at `data_dir/vane.db` and load the
    /// encryption key from `data_dir/secret.key` (or VANE_SECRET env).
    pub async fn open(data_dir: &Path) -> anyhow::Result<Self> {
        let key = load_or_create_key(data_dir)?;
        let db_path = data_dir.join("vane.db");
        let conn = Connection::open(&db_path).context("open sqlite db")?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = Self {
            key: Arc::new(key),
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK(id=1),
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 4455,
                safe_entry TEXT NOT NULL DEFAULT '',
                welcome_shown INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL DEFAULT '',
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS port_forwards (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT 'tcp',
                listen_port INTEGER NOT NULL,
                target_ip_enc TEXT NOT NULL DEFAULT '',
                target_port INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ddns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                domains_enc TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                sub_domain TEXT NOT NULL DEFAULT '',
                ip_version TEXT NOT NULL DEFAULT 'ipv4',
                ip_detect_mode TEXT NOT NULL DEFAULT 'api',
                ip_interface TEXT NOT NULL DEFAULT '',
                ip_index INTEGER NOT NULL DEFAULT 0,
                interval INTEGER NOT NULL DEFAULT 300,
                enabled INTEGER NOT NULL DEFAULT 0,
                provider_conf_enc TEXT NOT NULL DEFAULT '',
                last_ip TEXT NOT NULL DEFAULT '',
                last_updated TEXT NOT NULL DEFAULT '',
                ip_history_enc TEXT NOT NULL DEFAULT '',
                last_sync_ok INTEGER,
                last_sync_err TEXT NOT NULL DEFAULT '',
                last_sync_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_services (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                listen_port INTEGER NOT NULL,
                enable_https INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_routes (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                backend_url_enc TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 0,
                matched_cert_id TEXT NOT NULL DEFAULT '',
                cert_status TEXT NOT NULL DEFAULT '',
                auth_enabled INTEGER NOT NULL DEFAULT 0,
                auth_user TEXT NOT NULL DEFAULT '',
                auth_pass_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(service_id) REFERENCES web_services(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS tls_certs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                domains_enc TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'acme',
                ca_provider TEXT NOT NULL DEFAULT 'letsencrypt',
                provider TEXT NOT NULL DEFAULT '',
                provider_conf_enc TEXT NOT NULL DEFAULT '',
                cert_pem_enc TEXT NOT NULL DEFAULT '',
                key_pem_enc TEXT NOT NULL DEFAULT '',
                issued_at TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL DEFAULT '',
                auto_renew INTEGER NOT NULL DEFAULT 0,
                email TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                error_msg TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ip_filter_rules (
                id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                mode TEXT NOT NULL DEFAULT 'whitelist',
                scopes_enc TEXT NOT NULL DEFAULT '',
                manual_ips_enc TEXT NOT NULL DEFAULT '',
                attachments_enc TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_logs (
                id TEXT PRIMARY KEY,
                service_id TEXT NOT NULL DEFAULT '',
                route_id TEXT NOT NULL DEFAULT '',
                route_name TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                status_code INTEGER NOT NULL DEFAULT 0,
                client_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                auth_result TEXT NOT NULL DEFAULT '',
                time TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                success INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS backups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                data_enc TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        "#)?;
        // Non-destructive column additions for existing DBs
        let _ = conn.execute_batch("ALTER TABLE tls_certs ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0");
        let _ = conn.execute_batch("ALTER TABLE sessions ADD COLUMN username TEXT NOT NULL DEFAULT ''");
        Ok(())
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    pub async fn load_admin(&self) -> anyhow::Result<Option<AdminConfig>> {
        let conn = self.conn.lock().await;
        let result = conn.query_row(
            "SELECT username, password_hash, port, safe_entry, welcome_shown FROM admin WHERE id=1",
            [],
            |row| {
                Ok(AdminConfig {
                    username: row.get(0)?,
                    password_hash: row.get(1)?,
                    port: row.get(2)?,
                    safe_entry: row.get(3)?,
                    welcome_shown: row.get::<_, i64>(4)? != 0,
                })
            },
        ).optional()?;
        Ok(result)
    }

    pub async fn save_admin(&self, a: &AdminConfig) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO admin(id,username,password_hash,port,safe_entry,welcome_shown) VALUES(1,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash,
             port=excluded.port, safe_entry=excluded.safe_entry, welcome_shown=excluded.welcome_shown",
            params![a.username, a.password_hash, a.port, a.safe_entry, a.welcome_shown as i64],
        )?;
        Ok(())
    }

    // ─── Sessions ─────────────────────────────────────────────────────────────

    pub async fn save_session(&self, token: &str, username: &str, expires_at: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO sessions(token, username, expires_at) VALUES(?,?,?)",
            params![token, username, expires_at],
        )?;
        Ok(())
    }

    pub async fn delete_session(&self, token: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM sessions WHERE token=?", params![token])?;
        Ok(())
    }

    pub async fn delete_expired_sessions(&self, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", params![now])?;
        Ok(())
    }

    pub async fn delete_all_sessions(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM sessions", [])?;
        Ok(())
    }

    pub async fn load_sessions(&self) -> anyhow::Result<Vec<SessionInfo>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare("SELECT token, username, expires_at FROM sessions ORDER BY expires_at")?;
        let rows = stmt.query_map([], |row| {
            Ok(SessionInfo {
                token: row.get(0)?,
                username: row.get(1)?,
                created_at: String::new(), // expires_at stored, not created_at
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub async fn touch_session(&self, token: &str, new_exp: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("UPDATE sessions SET expires_at=? WHERE token=?", params![new_exp, token])?;
        Ok(())
    }

    pub async fn session_valid(&self, token: &str, now: i64) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().await;
        let result = conn.query_row(
            "SELECT username FROM sessions WHERE token=? AND expires_at > ?",
            params![token, now],
            |row| row.get::<_, String>(0),
        ).optional()?;
        Ok(result)
    }

    // ─── Port Forwards ────────────────────────────────────────────────────────

    pub async fn load_port_forwards(&self) -> anyhow::Result<Vec<PortForwardRule>> {
        let key = *self.key;
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, protocol, listen_port, target_ip_enc, target_port, enabled, created_at
             FROM port_forwards ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u16>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, u16>(5)?,
                row.get::<_, i64>(6)? != 0,
                row.get::<_, String>(7)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, name, protocol, listen_port, target_ip_enc, target_port, enabled, created_at) = row?;
            let target_ip = decrypt_str(&key, &target_ip_enc).unwrap_or_default();
            let mut r = PortForwardRule {
                id, name, protocol, listen_port, target_ip, target_port, enabled, created_at,
                ..Default::default()
            };
            r.normalize();
            result.push(r);
        }
        Ok(result)
    }

    pub async fn save_port_forward(&self, r: &PortForwardRule) -> anyhow::Result<()> {
        let key = *self.key;
        let target_ip_enc = encrypt_str(&key, &r.target_ip)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO port_forwards(id,name,protocol,listen_port,target_ip_enc,target_port,enabled,created_at)
             VALUES(?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, protocol=excluded.protocol,
             listen_port=excluded.listen_port, target_ip_enc=excluded.target_ip_enc,
             target_port=excluded.target_port, enabled=excluded.enabled",
            params![r.id, r.name, r.protocol, r.listen_port, target_ip_enc, r.target_port, r.enabled as i64, r.created_at],
        )?;
        Ok(())
    }

    pub async fn delete_port_forward(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM port_forwards WHERE id=?", params![id])?;
        Ok(())
    }

    // ─── DDNS ─────────────────────────────────────────────────────────────────

    pub async fn load_ddns(&self) -> anyhow::Result<Vec<DdnsRule>> {
        let key = *self.key;
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, provider, domains_enc, domain, sub_domain, ip_version, ip_detect_mode,
             ip_interface, ip_index, interval, enabled, provider_conf_enc, last_ip, last_updated,
             ip_history_enc, last_sync_ok, last_sync_err, last_sync_at, created_at
             FROM ddns ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i32>(9)?,
                row.get::<_, i32>(10)?,
                row.get::<_, i64>(11)? != 0,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, Option<i64>>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, String>(19)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, name, provider, domains_enc, domain, sub_domain, ip_version, ip_detect_mode,
                 ip_interface, ip_index, interval, enabled, provider_conf_enc, last_ip, last_updated,
                 ip_history_enc, last_sync_ok, last_sync_err, last_sync_at, created_at) = row?;
            let domains: Vec<String> = if domains_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &domains_enc).unwrap_or_default()
            };
            let provider_conf: ProviderConf = if provider_conf_enc.is_empty() { Default::default() } else {
                decrypt_json(&key, &provider_conf_enc).unwrap_or_default()
            };
            let ip_history: Vec<IpRecord> = if ip_history_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &ip_history_enc).unwrap_or_default()
            };
            result.push(DdnsRule {
                id, name, provider, domains, domain, sub_domain, ip_version, ip_detect_mode,
                ip_interface, ip_index, interval, enabled, provider_conf, last_ip, last_updated,
                ip_history, last_sync_ok: last_sync_ok.map(|v| v != 0), last_sync_err, last_sync_at,
                created_at,
                ..Default::default()
            });
        }
        Ok(result)
    }

    pub async fn save_ddns(&self, r: &DdnsRule) -> anyhow::Result<()> {
        let key = *self.key;
        let domains_enc = encrypt_json(&key, &r.domains)?;
        let provider_conf_enc = encrypt_json(&key, &r.provider_conf)?;
        let ip_history_enc = encrypt_json(&key, &r.ip_history)?;
        let last_sync_ok_val: Option<i64> = r.last_sync_ok.map(|v| if v { 1 } else { 0 });
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO ddns(id,name,provider,domains_enc,domain,sub_domain,ip_version,ip_detect_mode,
             ip_interface,ip_index,interval,enabled,provider_conf_enc,last_ip,last_updated,
             ip_history_enc,last_sync_ok,last_sync_err,last_sync_at,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, provider=excluded.provider,
             domains_enc=excluded.domains_enc, domain=excluded.domain, sub_domain=excluded.sub_domain,
             ip_version=excluded.ip_version, ip_detect_mode=excluded.ip_detect_mode,
             ip_interface=excluded.ip_interface, ip_index=excluded.ip_index, interval=excluded.interval,
             enabled=excluded.enabled, provider_conf_enc=excluded.provider_conf_enc,
             last_ip=excluded.last_ip, last_updated=excluded.last_updated,
             ip_history_enc=excluded.ip_history_enc, last_sync_ok=excluded.last_sync_ok,
             last_sync_err=excluded.last_sync_err, last_sync_at=excluded.last_sync_at",
            params![
                r.id, r.name, r.provider, domains_enc, r.domain, r.sub_domain,
                r.ip_version, r.ip_detect_mode, r.ip_interface, r.ip_index, r.interval,
                r.enabled as i64, provider_conf_enc, r.last_ip, r.last_updated,
                ip_history_enc, last_sync_ok_val, r.last_sync_err, r.last_sync_at, r.created_at
            ],
        )?;
        Ok(())
    }

    pub async fn delete_ddns(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM ddns WHERE id=?", params![id])?;
        Ok(())
    }

    // ─── Web Services ─────────────────────────────────────────────────────────

    pub async fn load_web_services(&self) -> anyhow::Result<Vec<WebServiceRule>> {
        let key = *self.key;
        let conn = self.conn.lock().await;
        let mut svc_stmt = conn.prepare(
            "SELECT id, name, listen_port, enable_https, enabled, created_at
             FROM web_services ORDER BY created_at"
        )?;
        let svcs: Vec<(String, String, u16, bool, bool, String)> = svc_stmt.query_map([], |row| {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?,
                row.get::<_, i64>(3)? != 0, row.get::<_, i64>(4)? != 0, row.get(5)?,
            ))
        })?.filter_map(|r| r.ok()).collect();

        let mut result = Vec::new();
        for (id, name, listen_port, enable_https, enabled, created_at) in svcs {
            let mut route_stmt = conn.prepare(
                "SELECT id, name, domain, backend_url_enc, enabled, matched_cert_id, cert_status,
                 auth_enabled, auth_user, auth_pass_hash, created_at
                 FROM web_routes WHERE service_id=? ORDER BY created_at"
            )?;
            let routes: Vec<WebRoute> = route_stmt.query_map(params![id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)? != 0,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)? != 0,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })?.filter_map(|r| r.ok()).map(|(rid, rname, domain, backend_enc, renabled,
                matched_cert_id, cert_status, auth_enabled, auth_user, auth_pass_hash, rcreated_at)| {
                let backend_url = decrypt_str(&key, &backend_enc).unwrap_or_default();
                WebRoute {
                    id: rid, name: rname, domain, backend_url, enabled: renabled,
                    matched_cert_id, cert_status, auth_enabled, auth_user, auth_pass_hash,
                    created_at: rcreated_at,
                }
            }).collect();

            result.push(WebServiceRule { id, name, listen_port, enable_https, enabled, routes, created_at });
        }
        Ok(result)
    }

    pub async fn save_web_service(&self, svc: &WebServiceRule) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO web_services(id,name,listen_port,enable_https,enabled,created_at)
             VALUES(?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, listen_port=excluded.listen_port,
             enable_https=excluded.enable_https, enabled=excluded.enabled",
            params![svc.id, svc.name, svc.listen_port, svc.enable_https as i64, svc.enabled as i64, svc.created_at],
        )?;
        Ok(())
    }

    pub async fn delete_web_service(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM web_services WHERE id=?", params![id])?;
        Ok(())
    }

    pub async fn save_web_route(&self, service_id: &str, route: &WebRoute) -> anyhow::Result<()> {
        let key = *self.key;
        let backend_enc = encrypt_str(&key, &route.backend_url)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO web_routes(id,service_id,name,domain,backend_url_enc,enabled,
             matched_cert_id,cert_status,auth_enabled,auth_user,auth_pass_hash,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, domain=excluded.domain,
             backend_url_enc=excluded.backend_url_enc, enabled=excluded.enabled,
             matched_cert_id=excluded.matched_cert_id, cert_status=excluded.cert_status,
             auth_enabled=excluded.auth_enabled, auth_user=excluded.auth_user,
             auth_pass_hash=excluded.auth_pass_hash",
            params![
                route.id, service_id, route.name, route.domain, backend_enc, route.enabled as i64,
                route.matched_cert_id, route.cert_status, route.auth_enabled as i64,
                route.auth_user, route.auth_pass_hash, route.created_at
            ],
        )?;
        Ok(())
    }

    pub async fn delete_web_route(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM web_routes WHERE id=?", params![id])?;
        Ok(())
    }

    // ─── TLS Certs ────────────────────────────────────────────────────────────

    pub async fn load_tls_certs(&self) -> anyhow::Result<Vec<TlsRule>> {
        let key = *self.key;
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, domains_enc, domain, source, ca_provider, provider, provider_conf_enc,
             cert_pem_enc, key_pem_enc, issued_at, expires_at, auto_renew, email, status, error_msg,
             enabled, created_at FROM tls_certs ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, i64>(12)? != 0,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, i64>(16)? != 0,
                row.get::<_, String>(17)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, name, domains_enc, domain, source, ca_provider, provider, provider_conf_enc,
                 cert_pem_enc, key_pem_enc, issued_at, expires_at, auto_renew, email, status,
                 error_msg, enabled, created_at) = row?;
            let domains: Vec<String> = if domains_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &domains_enc).unwrap_or_default()
            };
            let provider_conf: ProviderConf = if provider_conf_enc.is_empty() { Default::default() } else {
                decrypt_json(&key, &provider_conf_enc).unwrap_or_default()
            };
            let cert_pem = if cert_pem_enc.is_empty() { String::new() } else {
                decrypt_str(&key, &cert_pem_enc).unwrap_or_default()
            };
            let key_pem = if key_pem_enc.is_empty() { String::new() } else {
                decrypt_str(&key, &key_pem_enc).unwrap_or_default()
            };
            result.push(TlsRule {
                id, name, domains, domain, source, ca_provider, provider, provider_conf,
                cert_pem, key_pem, issued_at, expires_at, auto_renew, email, status,
                error_msg, enabled, created_at,
            });
        }
        Ok(result)
    }

    pub async fn save_tls_cert(&self, cert: &TlsRule) -> anyhow::Result<()> {
        let key = *self.key;
        let domains_enc = encrypt_json(&key, &cert.domains)?;
        let provider_conf_enc = encrypt_json(&key, &cert.provider_conf)?;
        let cert_pem_enc = if cert.cert_pem.is_empty() { String::new() } else { encrypt_str(&key, &cert.cert_pem)? };
        let key_pem_enc = if cert.key_pem.is_empty() { String::new() } else { encrypt_str(&key, &cert.key_pem)? };
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO tls_certs(id,name,domains_enc,domain,source,ca_provider,provider,
             provider_conf_enc,cert_pem_enc,key_pem_enc,issued_at,expires_at,auto_renew,
             email,status,error_msg,enabled,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, domains_enc=excluded.domains_enc,
             domain=excluded.domain, source=excluded.source, ca_provider=excluded.ca_provider,
             provider=excluded.provider, provider_conf_enc=excluded.provider_conf_enc,
             cert_pem_enc=excluded.cert_pem_enc, key_pem_enc=excluded.key_pem_enc,
             issued_at=excluded.issued_at, expires_at=excluded.expires_at,
             auto_renew=excluded.auto_renew, email=excluded.email, status=excluded.status,
             error_msg=excluded.error_msg, enabled=excluded.enabled",
            params![
                cert.id, cert.name, domains_enc, cert.domain, cert.source, cert.ca_provider,
                cert.provider, provider_conf_enc, cert_pem_enc, key_pem_enc, cert.issued_at,
                cert.expires_at, cert.auto_renew as i64, cert.email, cert.status,
                cert.error_msg, cert.enabled as i64, cert.created_at
            ],
        )?;
        Ok(())
    }

    pub async fn delete_tls_cert(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM tls_certs WHERE id=?", params![id])?;
        Ok(())
    }

    // ─── IP Filter ────────────────────────────────────────────────────────────

    pub async fn load_ip_filters(&self) -> anyhow::Result<Vec<IpFilterRule>> {
        let key = *self.key;
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, enabled, mode, scopes_enc, manual_ips_enc, attachments_enc, created_at
             FROM ip_filter_rules ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (id, enabled, mode, scopes_enc, manual_ips_enc, attachments_enc, created_at) = row?;
            let scopes: Vec<IpFilterScope> = if scopes_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &scopes_enc).unwrap_or_default()
            };
            let manual_ips: Vec<String> = if manual_ips_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &manual_ips_enc).unwrap_or_default()
            };
            let attachments: Vec<IpFilterAttachment> = if attachments_enc.is_empty() { vec![] } else {
                decrypt_json(&key, &attachments_enc).unwrap_or_default()
            };
            result.push(IpFilterRule { id, enabled, mode, scopes, manual_ips, attachments, created_at });
        }
        Ok(result)
    }

    pub async fn save_ip_filter(&self, rule: &IpFilterRule) -> anyhow::Result<()> {
        let key = *self.key;
        let scopes_enc = encrypt_json(&key, &rule.scopes)?;
        let manual_ips_enc = encrypt_json(&key, &rule.manual_ips)?;
        let attachments_enc = encrypt_json(&key, &rule.attachments)?;
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO ip_filter_rules(id,enabled,mode,scopes_enc,manual_ips_enc,attachments_enc,created_at)
             VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, mode=excluded.mode,
             scopes_enc=excluded.scopes_enc, manual_ips_enc=excluded.manual_ips_enc,
             attachments_enc=excluded.attachments_enc",
            params![rule.id, rule.enabled as i64, rule.mode, scopes_enc, manual_ips_enc, attachments_enc, rule.created_at],
        )?;
        Ok(())
    }

    pub async fn delete_ip_filter(&self, id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM ip_filter_rules WHERE id=?", params![id])?;
        Ok(())
    }

    // ─── Access Logs ──────────────────────────────────────────────────────────

    pub async fn append_access_log(&self, log: &AccessLog) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR IGNORE INTO access_logs(id,service_id,route_id,route_name,domain,
             status_code,client_ip,user_agent,auth_result,time)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
            params![log.id, log.service_id, log.route_id, log.route_name, log.domain,
                    log.status_code, log.client_ip, log.user_agent, log.auth_result, log.time],
        )?;
        Ok(())
    }

    pub async fn load_access_logs(&self, service_id: Option<&str>, limit: usize) -> anyhow::Result<Vec<AccessLog>> {
        let conn = self.conn.lock().await;
        let logs = if let Some(sid) = service_id {
            let mut stmt = conn.prepare(
                "SELECT id,service_id,route_id,route_name,domain,status_code,client_ip,user_agent,auth_result,time
                 FROM access_logs WHERE service_id=? ORDER BY time DESC LIMIT ?"
            )?;
            let x = stmt.query_map(params![sid, limit as i64], access_log_from_row)?
                .filter_map(|r| r.ok()).collect(); x
        } else {
            let mut stmt = conn.prepare(
                "SELECT id,service_id,route_id,route_name,domain,status_code,client_ip,user_agent,auth_result,time
                 FROM access_logs ORDER BY time DESC LIMIT ?"
            )?;
            let x = stmt.query_map(params![limit as i64], access_log_from_row)?
                .filter_map(|r| r.ok()).collect(); x
        };
        Ok(logs)
    }

    pub async fn clear_access_logs(&self, service_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM access_logs WHERE service_id=?", params![service_id])?;
        Ok(())
    }

    // ─── Admin Logs ───────────────────────────────────────────────────────────

    pub async fn append_admin_log(&self, log: &AdminLogRecord) -> anyhow::Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO admin_logs(ts,ip,action,success) VALUES(?,?,?,?)",
            params![log.ts, log.ip, log.action, log.success as i64],
        )?;
        // Keep only the last 1000 entries
        conn.execute(
            "DELETE FROM admin_logs WHERE id NOT IN (SELECT id FROM admin_logs ORDER BY id DESC LIMIT 1000)",
            [],
        )?;
        Ok(())
    }

    pub async fn load_admin_logs(&self, limit: usize) -> anyhow::Result<Vec<AdminLogRecord>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT ts, ip, action, success FROM admin_logs ORDER BY id DESC LIMIT ?"
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AdminLogRecord {
                ts: row.get(0)?,
                ip: row.get(1)?,
                action: row.get(2)?,
                success: row.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ─── Backup / Restore ─────────────────────────────────────────────────────

    /// Export all config as encrypted portable backup bytes.
    pub async fn export_backup(&self, data: &RuntimeData, admin: &AdminConfig) -> anyhow::Result<Vec<u8>> {
        let backup = FullBackup {
            version: "2".into(),
            admin: admin.clone(),
            portforward: data.portforward.clone(),
            ddns: data.ddns.clone(),
            webservice: data.webservice.clone(),
            tls: data.tls.clone(),
            ipfilter: data.ipfilter.clone(),
        };
        let key = portable_backup_key();
        let enc = encrypt_json(&key, &backup)?;
        Ok(enc.into_bytes())
    }

    /// Import an encrypted portable backup, returns the parsed data.
    pub async fn import_backup(&self, bytes: &[u8]) -> anyhow::Result<FullBackup> {
        let hex_str = std::str::from_utf8(bytes).context("backup not valid utf-8")?;
        let key = portable_backup_key();
        decrypt_json(&key, hex_str).context("invalid or unrecognised backup file")
    }

    /// Persist everything from a FullBackup into the database.
    pub async fn restore_from_backup(&self, backup: &FullBackup) -> anyhow::Result<()> {
        self.save_admin(&backup.admin).await?;
        // Clear existing data
        {
            let conn = self.conn.lock().await;
            conn.execute_batch("DELETE FROM port_forwards; DELETE FROM ddns; DELETE FROM web_services; DELETE FROM web_routes; DELETE FROM tls_certs; DELETE FROM ip_filter_rules;")?;
        }
        for r in &backup.portforward { self.save_port_forward(r).await?; }
        for r in &backup.ddns { self.save_ddns(r).await?; }
        for svc in &backup.webservice {
            self.save_web_service(svc).await?;
            for route in &svc.routes { self.save_web_route(&svc.id, route).await?; }
        }
        for cert in &backup.tls { self.save_tls_cert(cert).await?; }
        for rule in &backup.ipfilter { self.save_ip_filter(rule).await?; }
        Ok(())
    }
}

fn access_log_from_row(row: &rusqlite::Row) -> rusqlite::Result<AccessLog> {
    Ok(AccessLog {
        id: row.get(0)?,
        service_id: row.get(1)?,
        route_id: row.get(2)?,
        route_name: row.get(3)?,
        domain: row.get(4)?,
        status_code: row.get(5)?,
        client_ip: row.get(6)?,
        user_agent: row.get(7)?,
        auth_result: row.get(8)?,
        time: row.get(9)?,
    })
}

// ─── Key management ───────────────────────────────────────────────────────────

fn load_or_create_key(data_dir: &Path) -> anyhow::Result<[u8; 32]> {
    if let Ok(secret) = std::env::var(KEY_ENV) {
        return Ok(derive_key(&secret));
    }
    let key_file = data_dir.join("secret.key");
    if key_file.exists() {
        let encoded = std::fs::read_to_string(&key_file).context("read secret.key")?;
        let raw = hex::decode(encoded.trim()).context("decode secret.key")?;
        if raw.len() != 32 {
            bail!("invalid secret.key length");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(key);
    }
    // Generate new key
    use rand_core::RngCore;
    let mut raw = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut raw);
    let encoded = hex::encode(raw);
    std::fs::write(&key_file, &encoded).context("write secret.key")?;
    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(raw)
}

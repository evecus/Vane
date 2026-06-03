use crate::config::{crypto, types::*, ConfigInner};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ─── DataDir ──────────────────────────────────────────────────────────────────

pub struct DataDir {
    pub root: PathBuf,
    pub key: [u8; 32],
    db: Mutex<Connection>,
}

impl std::fmt::Debug for DataDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataDir({})", self.root.display())
    }
}

impl DataDir {
    pub fn open(custom_path: Option<&str>) -> Result<Arc<Self>> {
        let root = if let Some(p) = custom_path {
            std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p))
        } else {
            std::env::current_exe()
                .unwrap_or_else(|_| PathBuf::from("."))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("data")
        };

        std::fs::create_dir_all(&root)
            .with_context(|| format!("create data dir: {}", root.display()))?;

        let key = load_or_create_key(&root)?;
        let db = open_db(&root)?;
        migrate(&db)?;

        Ok(Arc::new(Self {
            root,
            key,
            db: Mutex::new(db),
        }))
    }

    pub fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.db.lock().unwrap();
        f(&conn)
    }
}

// ─── Key management ───────────────────────────────────────────────────────────

fn load_or_create_key(root: &PathBuf) -> Result<[u8; 32]> {
    // Env var override
    if let Ok(secret) = std::env::var("VANE_SECRET") {
        return Ok(crypto::derive_key(&secret));
    }

    let key_file = root.join("secret.key");
    if key_file.exists() {
        let hex = std::fs::read_to_string(&key_file)
            .context("read secret.key")?
            .trim()
            .to_string();
        let raw = hex::decode(&hex).context("decode secret.key")?;
        if raw.len() != 32 {
            anyhow::bail!("invalid secret.key: wrong length");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        Ok(key)
    } else {
        use rand::RngCore;
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        std::fs::write(&key_file, hex::encode(raw)).context("write secret.key")?;
        Ok(raw)
    }
}

// ─── Database open + migrate ──────────────────────────────────────────────────

fn open_db(root: &PathBuf) -> Result<Connection> {
    let path = root.join("vane.db");
    let conn = Connection::open(&path).with_context(|| format!("open db: {}", path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS backups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            data_enc TEXT NOT NULL,
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
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id  TEXT NOT NULL DEFAULT '',
            route_id    TEXT NOT NULL DEFAULT '',
            route_name  TEXT NOT NULL DEFAULT '',
            domain      TEXT NOT NULL DEFAULT '',
            client_ip   TEXT NOT NULL DEFAULT '',
            user_agent  TEXT NOT NULL DEFAULT '',
            time        TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_access_logs_time ON access_logs(time);
        CREATE TABLE IF NOT EXISTS admin_login_logs (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ip      TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            time    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_admin_login_logs_time ON admin_login_logs(time);
    "#,
    )?;
    Ok(())
}

// ─── Load all config from DB ──────────────────────────────────────────────────

pub fn load_from_db(dd: &DataDir) -> Result<ConfigInner> {
    dd.with_conn(|conn| {
        let key = &dd.key;
        let mut inner = ConfigInner::default();

        // Admin
        let admin_res = conn.query_row(
            "SELECT username, password_hash, port, safe_entry, welcome_shown FROM admin WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u16>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i32>(4)?,
                ))
            },
        );
        match admin_res {
            Ok((username, password_hash, port, safe_entry, welcome_shown)) => {
                inner.admin = AdminConfig {
                    username,
                    password_hash,
                    port,
                    safe_entry,
                    welcome_shown: welcome_shown == 1,
                };
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                init_defaults(&mut inner, conn)?;
            }
            Err(e) => return Err(e.into()),
        }

        // PortForwards
        {
            let mut stmt = conn.prepare(
                "SELECT id,name,protocol,listen_port,target_ip_enc,target_port,enabled,created_at FROM port_forwards ORDER BY created_at"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u16>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u16>(5)?,
                    row.get::<_, i32>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })?;
            for row in rows {
                let (id, name, protocol, listen_port, target_ip_enc, target_port, enabled, created_at) = row?;
                let target_ip = if target_ip_enc.is_empty() {
                    String::new()
                } else {
                    crypto::decrypt_str(key, &target_ip_enc).unwrap_or_default()
                };
                inner.port_forwards.push(PortForwardRule {
                    id, name, protocol, listen_port, target_ip, target_port,
                    enabled: enabled == 1, created_at,
                });
            }
        }

        // DDNS
        {
            let mut stmt = conn.prepare(
                "SELECT id,name,provider,domains_enc,domain,sub_domain,ip_version,ip_detect_mode,ip_interface,ip_index,interval,enabled,provider_conf_enc,last_ip,last_updated,ip_history_enc,last_sync_ok,last_sync_err,last_sync_at,created_at FROM ddns ORDER BY created_at"
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, i32>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<i32>>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, String>(19)?,
                ))
            })?;
            for row in rows {
                let (id, name, provider, domains_enc, domain, sub_domain,
                    ip_version, ip_detect_mode, ip_interface, ip_index, interval,
                    enabled, provider_conf_enc, last_ip, last_updated, ip_history_enc,
                    last_sync_ok_int, last_sync_err, last_sync_at, created_at) = row?;

                let domains = if domains_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &domains_enc).unwrap_or_default() };
                let provider_conf = if provider_conf_enc.is_empty() { ProviderConf::default() }
                    else { crypto::decrypt_json(key, &provider_conf_enc).unwrap_or_default() };
                let ip_history = if ip_history_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &ip_history_enc).unwrap_or_default() };
                let last_sync_ok = last_sync_ok_int.map(|v| v == 1);

                inner.ddns.push(DdnsRule {
                    id, name, provider, domains, domain, sub_domain,
                    ip_version, ip_detect_mode, ip_interface, ip_index, interval,
                    enabled: enabled == 1, provider_conf, last_ip, last_updated,
                    ip_history, created_at, last_sync_ok,
                    last_sync_err, last_sync_at,
                });
            }
        }

        // WebServices + Routes
        {
            let mut svc_stmt = conn.prepare(
                "SELECT id,name,listen_port,enable_https,enabled,created_at FROM web_services ORDER BY created_at"
            )?;
            let svcs: Vec<_> = svc_stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u16>(2)?,
                    row.get::<_, i32>(3)?,
                    row.get::<_, i32>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?.collect::<std::result::Result<Vec<_>, _>>()?;

            for (id, name, listen_port, enable_https, enabled, created_at) in svcs {
                let mut route_stmt = conn.prepare(
                    "SELECT id,name,domain,backend_url_enc,enabled,matched_cert_id,cert_status,auth_enabled,auth_user,auth_pass_hash,created_at FROM web_routes WHERE service_id=? ORDER BY created_at"
                )?;
                let routes: Vec<WebRoute> = route_stmt.query_map(params![&id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i32>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                })?.filter_map(|r| r.ok()).map(|(rid, rname, domain, backend_enc, renabled,
                    matched_cert_id, cert_status, auth_enabled, auth_user, auth_pass_hash, rcreated_at)| {
                    let backend_url = if backend_enc.is_empty() { String::new() }
                        else { crypto::decrypt_str(key, &backend_enc).unwrap_or_default() };
                    WebRoute {
                        id: rid, name: rname, domain, backend_url,
                        enabled: renabled == 1, matched_cert_id, cert_status,
                        auth_enabled: auth_enabled == 1, auth_user, auth_pass_hash,
                        created_at: rcreated_at,
                    }
                }).collect();

                inner.web_services.push(WebService {
                    id, name, listen_port,
                    enable_https: enable_https == 1,
                    enabled: enabled == 1,
                    routes, created_at,
                });
            }
        }

        // TLS Certs
        {
            let mut stmt = conn.prepare(
                "SELECT id,name,domains_enc,domain,source,ca_provider,provider,provider_conf_enc,cert_pem_enc,key_pem_enc,issued_at,expires_at,auto_renew,email,status,error_msg,created_at FROM tls_certs ORDER BY created_at"
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
                    row.get::<_, i32>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                ))
            })?;
            for row in rows {
                let (id, name, domains_enc, domain, source, ca_provider, provider,
                    provider_conf_enc, cert_pem_enc, key_pem_enc, issued_at, expires_at,
                    auto_renew, email, status, error_msg, created_at) = row?;
                let domains = if domains_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &domains_enc).unwrap_or_default() };
                let provider_conf = if provider_conf_enc.is_empty() { ProviderConf::default() }
                    else { crypto::decrypt_json(key, &provider_conf_enc).unwrap_or_default() };
                let cert_pem = if cert_pem_enc.is_empty() { String::new() }
                    else { crypto::decrypt_str(key, &cert_pem_enc).unwrap_or_default() };
                let key_pem = if key_pem_enc.is_empty() { String::new() }
                    else { crypto::decrypt_str(key, &key_pem_enc).unwrap_or_default() };

                inner.tls_certs.push(TlsCert {
                    id, name, domains, domain, source, ca_provider, provider,
                    provider_conf, cert_pem, key_pem, issued_at, expires_at,
                    auto_renew: auto_renew == 1, email, status, error_msg, created_at,
                });
            }
        }

        // IP Filter
        {
            let mut stmt = conn.prepare(
                "SELECT id,enabled,mode,scopes_enc,manual_ips_enc,attachments_enc,created_at FROM ip_filter_rules ORDER BY created_at"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?;
            for row in rows {
                let (id, enabled, mode, scopes_enc, manual_ips_enc, attachments_enc, created_at) = row?;
                let scopes = if scopes_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &scopes_enc).unwrap_or_default() };
                let manual_ips = if manual_ips_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &manual_ips_enc).unwrap_or_default() };
                let attachments = if attachments_enc.is_empty() { vec![] }
                    else { crypto::decrypt_json(key, &attachments_enc).unwrap_or_default() };
                inner.ip_filter.push(IpFilterRule {
                    id, enabled: enabled == 1, mode, scopes, manual_ips, attachments, created_at,
                });
            }
        }

        Ok(inner)
    })
}

fn init_defaults(inner: &mut ConfigInner, conn: &Connection) -> Result<()> {
    inner.admin = AdminConfig {
        username: "admin".into(),
        port: 4455,
        ..Default::default()
    };
    inner.admin.set_password("admin")?;
    save_admin_conn(conn, &inner.admin)?;
    Ok(())
}

// ─── Atomic save helpers ──────────────────────────────────────────────────────

pub fn save_admin(dd: &DataDir, admin: &AdminConfig) -> Result<()> {
    dd.with_conn(|conn| save_admin_conn(conn, admin))
}

fn save_admin_conn(conn: &Connection, admin: &AdminConfig) -> Result<()> {
    conn.execute(
        "INSERT INTO admin(id,username,password_hash,port,safe_entry,welcome_shown) VALUES(1,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash, port=excluded.port, safe_entry=excluded.safe_entry, welcome_shown=excluded.welcome_shown",
        params![admin.username, admin.password_hash, admin.port, admin.safe_entry, admin.welcome_shown as i32],
    )?;
    Ok(())
}

pub fn save_port_forward(dd: &DataDir, r: &PortForwardRule) -> Result<()> {
    let target_ip_enc = crypto::encrypt_str(&dd.key, &r.target_ip)?;
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO port_forwards(id,name,protocol,listen_port,target_ip_enc,target_port,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, protocol=excluded.protocol, listen_port=excluded.listen_port, target_ip_enc=excluded.target_ip_enc, target_port=excluded.target_port, enabled=excluded.enabled",
            params![r.id, r.name, r.protocol, r.listen_port, target_ip_enc, r.target_port, r.enabled as i32, r.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_port_forward(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM port_forwards WHERE id=?", params![id])?;
        Ok(())
    })
}

pub fn save_ddns(dd: &DataDir, r: &DdnsRule) -> Result<()> {
    let domains_enc = crypto::encrypt_json(&dd.key, &r.domains)?;
    let provider_conf_enc = crypto::encrypt_json(&dd.key, &r.provider_conf)?;
    let ip_history_enc = crypto::encrypt_json(&dd.key, &r.ip_history)?;
    let last_sync_ok_val: Option<i32> = r.last_sync_ok.map(|v| v as i32);
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO ddns(id,name,provider,domains_enc,domain,sub_domain,ip_version,ip_detect_mode,ip_interface,ip_index,interval,enabled,provider_conf_enc,last_ip,last_updated,ip_history_enc,last_sync_ok,last_sync_err,last_sync_at,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, provider=excluded.provider, domains_enc=excluded.domains_enc, domain=excluded.domain, sub_domain=excluded.sub_domain, ip_version=excluded.ip_version, ip_detect_mode=excluded.ip_detect_mode, ip_interface=excluded.ip_interface, ip_index=excluded.ip_index, interval=excluded.interval, enabled=excluded.enabled, provider_conf_enc=excluded.provider_conf_enc, last_ip=excluded.last_ip, last_updated=excluded.last_updated, ip_history_enc=excluded.ip_history_enc, last_sync_ok=excluded.last_sync_ok, last_sync_err=excluded.last_sync_err, last_sync_at=excluded.last_sync_at",
            params![r.id, r.name, r.provider, domains_enc, r.domain, r.sub_domain,
                r.ip_version, r.ip_detect_mode, r.ip_interface, r.ip_index, r.interval,
                r.enabled as i32, provider_conf_enc, r.last_ip, r.last_updated, ip_history_enc,
                last_sync_ok_val, r.last_sync_err, r.last_sync_at, r.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_ddns(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM ddns WHERE id=?", params![id])?;
        Ok(())
    })
}

pub fn save_web_service(dd: &DataDir, svc: &WebService) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO web_services(id,name,listen_port,enable_https,enabled,created_at) VALUES(?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, listen_port=excluded.listen_port, enable_https=excluded.enable_https, enabled=excluded.enabled",
            params![svc.id, svc.name, svc.listen_port, svc.enable_https as i32, svc.enabled as i32, svc.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_web_service(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM web_services WHERE id=?", params![id])?;
        Ok(())
    })
}

pub fn save_web_route(dd: &DataDir, svc_id: &str, route: &WebRoute) -> Result<()> {
    let backend_enc = crypto::encrypt_str(&dd.key, &route.backend_url)?;
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO web_routes(id,service_id,name,domain,backend_url_enc,enabled,matched_cert_id,cert_status,auth_enabled,auth_user,auth_pass_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, domain=excluded.domain, backend_url_enc=excluded.backend_url_enc, enabled=excluded.enabled, matched_cert_id=excluded.matched_cert_id, cert_status=excluded.cert_status, auth_enabled=excluded.auth_enabled, auth_user=excluded.auth_user, auth_pass_hash=excluded.auth_pass_hash",
            params![route.id, svc_id, route.name, route.domain, backend_enc, route.enabled as i32,
                route.matched_cert_id, route.cert_status, route.auth_enabled as i32, route.auth_user, route.auth_pass_hash, route.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_web_route(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM web_routes WHERE id=?", params![id])?;
        Ok(())
    })
}

pub fn save_tls_cert(dd: &DataDir, cert: &TlsCert) -> Result<()> {
    let domains_enc = crypto::encrypt_json(&dd.key, &cert.domains)?;
    let provider_conf_enc = crypto::encrypt_json(&dd.key, &cert.provider_conf)?;
    let cert_pem_enc = if cert.cert_pem.is_empty() {
        String::new()
    } else {
        crypto::encrypt_str(&dd.key, &cert.cert_pem)?
    };
    let key_pem_enc = if cert.key_pem.is_empty() {
        String::new()
    } else {
        crypto::encrypt_str(&dd.key, &cert.key_pem)?
    };
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO tls_certs(id,name,domains_enc,domain,source,ca_provider,provider,provider_conf_enc,cert_pem_enc,key_pem_enc,issued_at,expires_at,auto_renew,email,status,error_msg,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET name=excluded.name, domains_enc=excluded.domains_enc, domain=excluded.domain, source=excluded.source, ca_provider=excluded.ca_provider, provider=excluded.provider, provider_conf_enc=excluded.provider_conf_enc, cert_pem_enc=excluded.cert_pem_enc, key_pem_enc=excluded.key_pem_enc, issued_at=excluded.issued_at, expires_at=excluded.expires_at, auto_renew=excluded.auto_renew, email=excluded.email, status=excluded.status, error_msg=excluded.error_msg",
            params![cert.id, cert.name, domains_enc, cert.domain, cert.source, cert.ca_provider, cert.provider,
                provider_conf_enc, cert_pem_enc, key_pem_enc, cert.issued_at, cert.expires_at,
                cert.auto_renew as i32, cert.email, cert.status, cert.error_msg, cert.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_tls_cert(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM tls_certs WHERE id=?", params![id])?;
        Ok(())
    })
}

pub fn save_ip_filter_rule(dd: &DataDir, rule: &IpFilterRule) -> Result<()> {
    let scopes_enc = crypto::encrypt_json(&dd.key, &rule.scopes)?;
    let manual_ips_enc = crypto::encrypt_json(&dd.key, &rule.manual_ips)?;
    let attachments_enc = crypto::encrypt_json(&dd.key, &rule.attachments)?;
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO ip_filter_rules(id,enabled,mode,scopes_enc,manual_ips_enc,attachments_enc,created_at) VALUES(?,?,?,?,?,?,?)
             ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, mode=excluded.mode, scopes_enc=excluded.scopes_enc, manual_ips_enc=excluded.manual_ips_enc, attachments_enc=excluded.attachments_enc",
            params![rule.id, rule.enabled as i32, rule.mode, scopes_enc, manual_ips_enc, attachments_enc, rule.created_at],
        )?;
        Ok(())
    })
}

pub fn delete_ip_filter_rule(dd: &DataDir, id: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM ip_filter_rules WHERE id=?", params![id])?;
        Ok(())
    })
}

// ─── Session management ───────────────────────────────────────────────────────

pub fn session_set(dd: &DataDir, token: &str, expires_at: i64) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO sessions(token, expires_at) VALUES(?,?) ON CONFLICT(token) DO UPDATE SET expires_at=excluded.expires_at",
            params![token, expires_at],
        )?;
        Ok(())
    })
}

pub fn session_get(dd: &DataDir, token: &str) -> Result<Option<i64>> {
    dd.with_conn(|conn| {
        let res = conn.query_row(
            "SELECT expires_at FROM sessions WHERE token=?",
            params![token],
            |row| row.get::<_, i64>(0),
        );
        match res {
            Ok(exp) => Ok(Some(exp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    })
}

pub fn session_delete(dd: &DataDir, token: &str) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM sessions WHERE token=?", params![token])?;
        Ok(())
    })
}

pub fn session_delete_all(dd: &DataDir) -> Result<()> {
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM sessions", [])?;
        Ok(())
    })
}

pub fn session_purge_expired(dd: &DataDir) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    dd.with_conn(|conn| {
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", params![now])?;
        Ok(())
    })
}

// ─── Access log persistence ───────────────────────────────────────────────────

/// Batch-insert web-service access log entries.
/// Older rows are trimmed so the table never exceeds `keep` rows total.
pub fn flush_access_logs(
    dd: &DataDir,
    logs: &[crate::module::webservice::AccessLog],
    keep: usize,
) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    dd.with_conn(|conn| {
        let tx = conn.unchecked_transaction()?;
        for l in logs {
            tx.execute(
                "INSERT INTO access_logs(service_id,route_id,route_name,domain,client_ip,user_agent,time) VALUES(?,?,?,?,?,?,?)",
                params![l.service_id, l.route_id, l.route_name, l.domain, l.client_ip, l.user_agent, l.time],
            )?;
        }
        // Keep only the newest `keep` rows
        tx.execute(
            "DELETE FROM access_logs WHERE id NOT IN (SELECT id FROM access_logs ORDER BY id DESC LIMIT ?)",
            params![keep as i64],
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn load_access_logs(
    dd: &DataDir,
    service_id: &str,
    limit: usize,
) -> Result<Vec<crate::module::webservice::AccessLog>> {
    dd.with_conn(|conn| {
        let sql = if service_id.is_empty() {
            "SELECT service_id,route_id,route_name,domain,client_ip,user_agent,time FROM access_logs ORDER BY id DESC LIMIT ?1".to_string()
        } else {
            "SELECT service_id,route_id,route_name,domain,client_ip,user_agent,time FROM access_logs WHERE service_id=?2 ORDER BY id DESC LIMIT ?1".to_string()
        };
        let mut stmt = conn.prepare(&sql)?;
        let rows = if service_id.is_empty() {
            stmt.query_map(params![limit as i64], row_to_access_log)?
                .collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![limit as i64, service_id], row_to_access_log)?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        Ok(rows)
    })
}

fn row_to_access_log(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::module::webservice::AccessLog> {
    Ok(crate::module::webservice::AccessLog {
        service_id: row.get(0)?,
        route_id: row.get(1)?,
        route_name: row.get(2)?,
        domain: row.get(3)?,
        client_ip: row.get(4)?,
        user_agent: row.get(5)?,
        time: row.get(6)?,
    })
}

// ─── Admin login log persistence ──────────────────────────────────────────────

pub fn flush_admin_login_logs(
    dd: &DataDir,
    logs: &[crate::api::auth::AdminLoginRecord],
    keep: usize,
) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    dd.with_conn(|conn| {
        let tx = conn.unchecked_transaction()?;
        for l in logs {
            tx.execute(
                "INSERT INTO admin_login_logs(ip,success,time) VALUES(?,?,?)",
                params![l.ip, l.success as i32, l.time],
            )?;
        }
        tx.execute(
            "DELETE FROM admin_login_logs WHERE id NOT IN (SELECT id FROM admin_login_logs ORDER BY id DESC LIMIT ?)",
            params![keep as i64],
        )?;
        tx.commit()?;
        Ok(())
    })
}

pub fn load_admin_login_logs(
    dd: &DataDir,
    limit: usize,
) -> Result<Vec<crate::api::auth::AdminLoginRecord>> {
    dd.with_conn(|conn| {
        let mut stmt =
            conn.prepare("SELECT ip,success,time FROM admin_login_logs ORDER BY id DESC LIMIT ?")?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(crate::api::auth::AdminLoginRecord {
                    ip: row.get(0)?,
                    success: row.get::<_, i32>(1)? == 1,
                    time: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

// ─── Backup ───────────────────────────────────────────────────────────────────

pub fn save_backup(dd: &DataDir, name: &str, data_enc: &str) -> Result<()> {
    let id = new_id();
    let created_at = now_rfc3339();
    dd.with_conn(|conn| {
        conn.execute(
            "INSERT INTO backups(id,name,data_enc,created_at) VALUES(?,?,?,?)",
            params![id, name, data_enc, created_at],
        )?;
        Ok(())
    })
}

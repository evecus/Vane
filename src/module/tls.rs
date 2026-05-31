use crate::config::{db, Config, TlsCert};
use anyhow::{anyhow, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

const ZEROSSL_DIR: &str = "https://acme.zerossl.com/v2/DV90";

// ─── Manager ──────────────────────────────────────────────────────────────────

pub struct Manager {
    cfg: Config,
    in_flight: Arc<Mutex<HashSet<String>>>,
}

impl Manager {
    pub fn new(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn start_auto_renew(self: &Arc<Self>) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            sleep(Duration::from_secs(30)).await;
            mgr.renew_all().await;
            let mut ticker = tokio::time::interval(Duration::from_secs(12 * 3600));
            loop {
                ticker.tick().await;
                mgr.renew_all().await;
            }
        });
    }

    async fn renew_all(self: &Arc<Self>) {
        let certs: Vec<TlsCert> = self.cfg.read().tls_certs.clone();
        for cert in certs {
            if !cert.auto_renew || cert.source != "acme" { continue; }
            if cert.status == "error" { continue; }
            let days = cert.days_until_expiry();
            if days > 30 && cert.status == "active" { continue; }
            info!("[tls] auto-renew: cert {:?} expires in {} days", cert.domain, days);
            if let Err(e) = self.issue_cert(&cert.id).await {
                error!("[tls] auto-renew failed for {:?}: {}", cert.domain, e);
            } else {
                info!("[tls] auto-renew: cert {:?} renewed", cert.domain);
            }
        }
    }

    pub async fn issue_cert(self: &Arc<Self>, cert_id: &str) -> Result<()> {
        // Deduplicate in-flight
        {
            let mut inflight = self.in_flight.lock().unwrap();
            if inflight.contains(cert_id) {
                return Err(anyhow!("certificate issuance already in progress for {}", cert_id));
            }
            inflight.insert(cert_id.to_string());
        }
        let inflight_clone = Arc::clone(&self.in_flight);
        let cert_id_owned = cert_id.to_string();
        scopeguard::defer! {
            inflight_clone.lock().unwrap().remove(&cert_id_owned);
        }

        let cert = {
            let cfg = self.cfg.read();
            cfg.tls_certs.iter().find(|c| c.id == cert_id).cloned()
        };
        let cert = cert.ok_or_else(|| anyhow!("cert {} not found", cert_id))?;

        if cert.email.is_empty() {
            return Err(anyhow!("email address is required for ACME certificate issuance"));
        }

        let domains: Vec<String> = if !cert.domains.is_empty() {
            cert.domains.clone()
        } else if !cert.domain.is_empty() {
            vec![cert.domain.clone()]
        } else {
            return Err(anyhow!("no domains specified for cert {}", cert_id));
        };

        self.update_cert_status(cert_id, "pending", "");

        info!("[tls] IssueCert start: id={} ca={:?} domains={:?}", cert_id, cert.ca_provider, domains);

        let result = self.do_issue(&cert, &domains).await;
        match result {
            Ok((cert_pem, key_pem, expires_at)) => {
                let domain = domains[0].clone();
                let now = crate::config::types::now_rfc3339();
                {
                    let mut cfg = self.cfg.write();
                    if let Some(c) = cfg.tls_certs.iter_mut().find(|c| c.id == cert_id) {
                        c.cert_pem = cert_pem;
                        c.key_pem = key_pem;
                        c.issued_at = now;
                        c.expires_at = expires_at;
                        c.status = "active".into();
                        c.error_msg = String::new();
                        if !domains.is_empty() { c.domain = domain; }
                    }
                }
                let dd = self.cfg.read().data_dir.clone();
                if let Some(dd) = dd {
                    let snap = self.cfg.read().tls_certs.iter().find(|c| c.id == cert_id).cloned();
                    if let Some(snap) = snap { db::save_tls_cert(&dd, &snap)?; }
                }
                Ok(())
            }
            Err(e) => {
                self.update_cert_status(cert_id, "error", &e.to_string());
                let dd = self.cfg.read().data_dir.clone();
                if let Some(dd) = dd {
                    let snap = self.cfg.read().tls_certs.iter().find(|c| c.id == cert_id).cloned();
                    if let Some(snap) = snap { let _ = db::save_tls_cert(&dd, &snap); }
                }
                Err(e)
            }
        }
    }

    async fn do_issue(&self, cert: &TlsCert, domains: &[String]) -> Result<(String, String, String)> {
        let server_url = if cert.ca_provider == "zerossl" {
            ZEROSSL_DIR.to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        };

        let (account, _creds) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", cert.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &server_url,
            None,
        ).await.context("create ACME account")?;

        let identifiers: Vec<Identifier> = domains.iter()
            .map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder { identifiers: &identifiers })
            .await.context("create order")?;

        let authorizations = order.authorizations().await.context("get authorizations")?;

        let token = &cert.provider_conf.api_token;
        let zone_id = &cert.provider_conf.zone_id;
        let mut dns_records: Vec<(String, String, String)> = Vec::new();

        for authz in &authorizations {
            // Check if already valid using matches!
            if matches!(authz.status, AuthorizationStatus::Valid) { continue; }

            let challenge = authz.challenges.iter()
                .find(|c| matches!(c.r#type, ChallengeType::Dns01))
                .ok_or_else(|| anyhow!("no DNS-01 challenge"))?;

            let dns_value = order.key_authorization(challenge).dns_value();
            let domain = match &authz.identifier {
                Identifier::Dns(d) => d.clone(),
            };
            let txt_name = format!("_acme-challenge.{}", domain);

            let (resolved_zone_id, record_id) = cf_create_txt_record(token, zone_id, &txt_name, &dns_value).await
                .with_context(|| format!("create TXT record for {}", domain))?;
            dns_records.push((resolved_zone_id, record_id, txt_name.clone()));
            info!("[tls] TXT record created for {} value={}", txt_name, dns_value);

            // 等待 DNS 传播再通知 ACME 服务器验证。
            // Cloudflare 本身几秒内就生效，但 Let's Encrypt 的验证服务器需要
            // 从权威 DNS 查询，实际传播可能需要 30-90 秒。
            info!("[tls] waiting 90s for DNS propagation before notifying ACME...");
            sleep(Duration::from_secs(90)).await;

            order.set_challenge_ready(&challenge.url).await
                .context("set challenge ready")?;
            info!("[tls] notified ACME challenge ready for {}", domain);
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            sleep(Duration::from_secs(15)).await;
            order.refresh().await.context("refresh order")?;
            let state = order.state();
            info!("[tls] order status: {:?}", state.status);
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => {
                    // 记录 ACME 服务器返回的具体拒绝原因
                    let reason = format!("{:?}", state);
                    cleanup_txt_records(token, &dns_records).await;
                    return Err(anyhow!("ACME order invalid: {}", reason));
                }
                _ => {}
            }
            if std::time::Instant::now() > deadline {
                cleanup_txt_records(token, &dns_records).await;
                return Err(anyhow!("ACME DNS-01 challenge timed out after 600s"));
            }
        }

        let key_pair = KeyPair::generate().context("generate key pair")?;
        let mut params = CertificateParams::new(domains.to_vec()).context("cert params")?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&key_pair).context("serialize CSR")?;
        let csr_der = csr.der().to_vec();

        order.finalize(&csr_der).await.context("finalize order")?;

        let cert_chain_pem = loop {
            sleep(Duration::from_secs(5)).await;
            order.refresh().await.context("refresh order after finalize")?;
            match order.state().status {
                OrderStatus::Valid => {
                    break order.certificate().await.context("get certificate")?
                        .ok_or_else(|| anyhow!("no certificate in order"))?;
                }
                OrderStatus::Invalid => {
                    cleanup_txt_records(token, &dns_records).await;
                    return Err(anyhow!("ACME order invalid after finalize"));
                }
                _ => {}
            }
        };

        cleanup_txt_records(token, &dns_records).await;

        let key_pem = key_pair.serialize_pem();
        let expires_at = parse_cert_expiry(&cert_chain_pem).unwrap_or_default();
        info!("[tls] certificate issued successfully, expires: {}", expires_at);

        Ok((cert_chain_pem, key_pem, expires_at))
    }

    fn update_cert_status(&self, cert_id: &str, status: &str, error_msg: &str) {
        let mut cfg = self.cfg.write();
        if let Some(c) = cfg.tls_certs.iter_mut().find(|c| c.id == cert_id) {
            c.status = status.to_string();
            c.error_msg = error_msg.to_string();
        }
    }
}

// ─── Cloudflare DNS-01 ────────────────────────────────────────────────────────

async fn cf_resolve_zone(token: &str, zone_id_hint: &str, fqdn: &str) -> Result<String> {
    if !zone_id_hint.is_empty() {
        return Ok(zone_id_hint.to_string());
    }
    let client = reqwest::Client::new();
    let resp = client.get("https://api.cloudflare.com/client/v4/zones?per_page=100")
        .bearer_auth(token).send().await?.json::<serde_json::Value>().await?;
    let zones = resp["result"].as_array().ok_or_else(|| anyhow!("no zones"))?;
    let map: std::collections::HashMap<String, String> = zones.iter().filter_map(|z| {
        Some((z["name"].as_str()?.to_string(), z["id"].as_str()?.to_string()))
    }).collect();
    let parts: Vec<&str> = fqdn.split('.').collect();
    for n in 2..=parts.len().min(20) {
        let candidate = parts[parts.len() - n..].join(".");
        if let Some(id) = map.get(&candidate) { return Ok(id.clone()); }
    }
    Err(anyhow!("cloudflare: no zone found for {}", fqdn))
}

async fn cf_create_txt_record(token: &str, zone_id_hint: &str, name: &str, value: &str) -> Result<(String, String)> {
    let client = reqwest::Client::new();
    let zone_id = cf_resolve_zone(token, zone_id_hint, name).await?;
    let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id);
    let body = serde_json::json!({"type": "TXT", "name": name, "content": value, "ttl": 60});
    let resp = client.post(&url).bearer_auth(token).json(&body).send().await?
        .json::<serde_json::Value>().await?;
    if resp["success"].as_bool() != Some(true) {
        let msg = resp["errors"].as_array().and_then(|a| a.first())
            .and_then(|e| e["message"].as_str()).unwrap_or("unknown");
        return Err(anyhow!("cloudflare create TXT: {}", msg));
    }
    let record_id = resp["result"]["id"].as_str()
        .ok_or_else(|| anyhow!("no record id"))?.to_string();
    Ok((zone_id, record_id))
}

async fn cleanup_txt_records(token: &str, records: &[(String, String, String)]) {
    let client = reqwest::Client::new();
    for (zone_id, record_id, name) in records {
        let url = format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id);
        match client.delete(&url).bearer_auth(token).send().await {
            Ok(_) => info!("[tls] deleted TXT record for {}", name),
            Err(e) => warn!("[tls] failed to delete TXT record for {}: {}", name, e),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

pub fn parse_cert_expiry(cert_pem: &str) -> Option<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    let der_certs: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok()).collect();
    let der = der_certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after = parsed.validity().not_after.to_datetime();
    let ts = not_after.unix_timestamp();
    // Format as RFC3339: YYYY-MM-DDTHH:MM:SSZ
    let secs_in_day = 86400i64;
    let days_since_epoch = ts / secs_in_day;
    let time_of_day = ts % secs_in_day;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    let (year, month, day) = approx_ymd(days_since_epoch);
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, h, m, s))
}

fn approx_ymd(days: i64) -> (i64, i64, i64) {
    // Approximate gregorian calendar conversion
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let days_in_year = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 366 } else { 365 };
        if d < days_in_year { break; }
        d -= days_in_year;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: [i64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1i64;
    for &md in &month_days {
        if d < md { break; }
        d -= md;
        month += 1;
    }
    (y, month, d + 1)
}

pub fn extract_domains_from_cert_pem(cert_pem: &str) -> Vec<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    let der_certs: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok()).collect();
    let Some(der) = der_certs.first() else { return vec![] };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der) else { return vec![] };

    let mut domains = std::collections::HashSet::new();
    if let Ok(san) = parsed.subject_alternative_name() {
        if let Some(san) = san {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = name {
                    domains.insert(d.to_string());
                }
            }
        }
    }
    if domains.is_empty() {
        if let Some(cn) = parsed.subject().iter_common_name().next() {
            if let Ok(s) = cn.as_str() { domains.insert(s.to_string()); }
        }
    }
    domains.into_iter().collect()
}

use crate::config::{db, Config, ProviderConf, TlsCert};
use anyhow::{anyhow, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, ExternalAccountKey, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

const ZEROSSL_DIR: &str = "https://acme.zerossl.com/v2/DV90";

/// 内置 ZeroSSL EAB 账号。key: 邮箱, value: (kid, hmac_key_base64url)
/// 与 Go 版保持完全一致，用户选择对应邮箱时自动注入 EAB，无需手动填写。
static BUILTIN_ZEROSSL_ACCOUNTS: &[(&str, &str, &str)] = &[
    (
        "76q7n@dollicons.com",
        "JhL5gkVe0-zPKoH5G6_Z5A",
        "L24OuPHmeUS3RyN9wp28eaJqTBrYT7BVBXvHU3BvmNOh85Mpx3nz65sKsiY1Cik4jrAVKNvFVdRFk69tfT0tAQ",
    ),
    (
        "jamie@gmail.com",
        "RumPLRDS1IaG5YrHKUqG-g",
        "Opr7ZlT9t1g2Mp3nwMjn1dl9sUC2-yp6pGjf-E2PzGXBJTXoLsp_gPzv35eS0zK4mw6nQPCIDUPJcF5632jalw",
    ),
    (
        "gings@gmail.com",
        "16nmO6yCbhkm_Ny6sphJuQ",
        "hPOv1bdSDCNTJmASQvzXqJICcOuPxuBUEOnp7zFVnAzKimJMfSbL9RHGkyY2Pig_bwgcseSWU0XUcsY_OQnEbQ",
    ),
];

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
            if !cert.auto_renew || cert.source != "acme" {
                continue;
            }
            if cert.status == "error" {
                continue;
            }
            let days = cert.days_until_expiry();
            if days > 30 && cert.status == "active" {
                continue;
            }
            info!(
                "[tls] auto-renew: cert {:?} expires in {} days",
                cert.domain, days
            );
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
                return Err(anyhow!(
                    "certificate issuance already in progress for {}",
                    cert_id
                ));
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
            return Err(anyhow!(
                "email address is required for ACME certificate issuance"
            ));
        }

        let domains: Vec<String> = if !cert.domains.is_empty() {
            cert.domains.clone()
        } else if !cert.domain.is_empty() {
            vec![cert.domain.clone()]
        } else {
            return Err(anyhow!("no domains specified for cert {}", cert_id));
        };

        self.update_cert_status(cert_id, "pending", "");

        info!(
            "[tls] IssueCert start: id={} ca={:?} domains={:?}",
            cert_id, cert.ca_provider, domains
        );

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
                        if !domains.is_empty() {
                            c.domain = domain;
                        }
                    }
                }
                let dd = self.cfg.read().data_dir.clone();
                if let Some(dd) = dd {
                    let snap = self
                        .cfg
                        .read()
                        .tls_certs
                        .iter()
                        .find(|c| c.id == cert_id)
                        .cloned();
                    if let Some(snap) = snap {
                        db::save_tls_cert(&dd, &snap)?;
                    }
                }
                Ok(())
            }
            Err(e) => {
                self.update_cert_status(cert_id, "error", &e.to_string());
                let dd = self.cfg.read().data_dir.clone();
                if let Some(dd) = dd {
                    let snap = self
                        .cfg
                        .read()
                        .tls_certs
                        .iter()
                        .find(|c| c.id == cert_id)
                        .cloned();
                    if let Some(snap) = snap {
                        let _ = db::save_tls_cert(&dd, &snap);
                    }
                }
                Err(e)
            }
        }
    }

    async fn do_issue(
        &self,
        cert: &TlsCert,
        domains: &[String],
    ) -> Result<(String, String, String)> {
        let server_url = if cert.ca_provider == "zerossl" {
            ZEROSSL_DIR.to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        };

        // ZeroSSL 需要 EAB（External Account Binding）才能注册 ACME 账号。
        //
        // EAB 来源优先级（与 Go 版保持一致）：
        //   1. provider_conf.zerossl_key_id / zerossl_api_key
        //      前端"使用私有账号=关闭"时，会把内置账号的 kid+hmac 直接写入这两个字段后
        //      调用 PUT /tls/:id 保存，再 POST /tls/:id/issue；
        //      前端"使用私有账号=开启"时，用户手动填写的也存在这两个字段。
        //   2. 如果上面为空，尝试用 cert.email 匹配内置账号（auto-fix，兼容旧数据）。
        //   3. 都没有 → 报错，ZeroSSL 无法注册。
        let eab_kid_hmac: Option<(String, Vec<u8>)> = if cert.ca_provider == "zerossl" {
            // 1. 优先读 provider_conf 里的 zerossl_key_id / zerossl_api_key
            let (kid_str, hmac_str) = if !cert.provider_conf.zerossl_key_id.is_empty()
                && !cert.provider_conf.zerossl_api_key.is_empty()
            {
                (
                    cert.provider_conf.zerossl_key_id.clone(),
                    cert.provider_conf.zerossl_api_key.clone(),
                )
            } else {
                // 2. fallback：用 email 匹配内置账号（兼容旧数据）
                BUILTIN_ZEROSSL_ACCOUNTS
                    .iter()
                    .find(|(email, _, _)| *email == cert.email.as_str())
                    .map(|(_, kid, hmac)| (kid.to_string(), hmac.to_string()))
                    .unwrap_or_default()
            };

            if kid_str.is_empty() || hmac_str.is_empty() {
                return Err(anyhow!(
                    "ZeroSSL 需要 EAB 凭据（EAB Key ID 和 EAB HMAC Key），请在证书设置中填写或选择内置账号"
                ));
            }

            match base64_url_decode(&hmac_str) {
                Ok(raw) => {
                    info!("[tls] using ZeroSSL EAB kid={}", kid_str);
                    Some((kid_str, raw))
                }
                Err(e) => {
                    return Err(anyhow!(
                        "ZeroSSL HMAC key 解码失败: {}（应为 Base64url 格式）",
                        e
                    ));
                }
            }
        } else {
            None
        };

        let external_account = eab_kid_hmac
            .as_ref()
            .map(|(kid, key_bytes)| ExternalAccountKey::new(kid.clone(), key_bytes));

        let (account, _creds) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", cert.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &server_url,
            external_account.as_ref(),
        )
        .await
        .context("create ACME account")?;

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("create order")?;

        let authorizations = order.authorizations().await.context("get authorizations")?;

        let provider = cert.provider.as_str();
        let provider_conf = &cert.provider_conf;
        // (record_ref_a, record_ref_b, txt_name) — 语义随服务商而变：
        //   cloudflare   → (zone_id, record_id, name)
        //   alidns       → ("",      record_id, name)
        //   tencentcloud → ("",      record_id, name)
        let mut dns_records: Vec<(String, String, String)> = Vec::new();

        for authz in &authorizations {
            // Check if already valid using matches!
            if matches!(authz.status, AuthorizationStatus::Valid) {
                continue;
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| matches!(c.r#type, ChallengeType::Dns01))
                .ok_or_else(|| anyhow!("no DNS-01 challenge"))?;

            let dns_value = order.key_authorization(challenge).dns_value();
            let domain = match &authz.identifier {
                Identifier::Dns(d) => d.clone(),
            };
            let txt_name = format!("_acme-challenge.{}", domain);

            let (record_ref_a, record_id) =
                create_txt_record(provider, provider_conf, &txt_name, &dns_value)
                    .await
                    .with_context(|| format!("create TXT record for {}", domain))?;
            dns_records.push((record_ref_a, record_id, txt_name.clone()));
            info!(
                "[tls] TXT record created for {} value={}",
                txt_name, dns_value
            );

            // 等待 DNS 传播再通知 ACME 服务器验证。
            // 各服务商生效速度不同（Cloudflare 几秒，阿里云/腾讯云通常几十秒），
            // 但 Let's Encrypt 的验证服务器需要从权威 DNS 查询，实际传播可能需要 30-90 秒。
            info!("[tls] waiting 90s for DNS propagation before notifying ACME...");
            sleep(Duration::from_secs(90)).await;

            order
                .set_challenge_ready(&challenge.url)
                .await
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
                    cleanup_txt_records(provider, provider_conf, &dns_records).await;
                    return Err(anyhow!("ACME order invalid: {}", reason));
                }
                _ => {}
            }
            if std::time::Instant::now() > deadline {
                cleanup_txt_records(provider, provider_conf, &dns_records).await;
                return Err(anyhow!("ACME DNS-01 challenge timed out after 600s"));
            }
        }

        let key_pair = KeyPair::generate().context("generate key pair")?;
        let mut params = CertificateParams::new(domains.to_vec()).context("cert params")?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .context("serialize CSR")?;
        let csr_der = csr.der().to_vec();

        order.finalize(&csr_der).await.context("finalize order")?;

        let cert_chain_pem = loop {
            sleep(Duration::from_secs(5)).await;
            order
                .refresh()
                .await
                .context("refresh order after finalize")?;
            match order.state().status {
                OrderStatus::Valid => {
                    break order
                        .certificate()
                        .await
                        .context("get certificate")?
                        .ok_or_else(|| anyhow!("no certificate in order"))?;
                }
                OrderStatus::Invalid => {
                    cleanup_txt_records(provider, provider_conf, &dns_records).await;
                    return Err(anyhow!("ACME order invalid after finalize"));
                }
                _ => {}
            }
        };

        cleanup_txt_records(provider, provider_conf, &dns_records).await;

        let key_pem = key_pair.serialize_pem();
        let expires_at = parse_cert_expiry(&cert_chain_pem).unwrap_or_default();
        info!(
            "[tls] certificate issued successfully, expires: {}",
            expires_at
        );

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

// ─── DNS-01 服务商分发 ─────────────────────────────────────────────────────────
//
// 统一封装各 DNS 服务商的 TXT 记录增删。record_ref_a 的含义随服务商而变：
//   cloudflare   → zone_id（用于删除时定位 zone）
//   alidns       → ""（阿里云删除记录只需 record_id）
//   tencentcloud → ""（腾讯云删除记录只需 record_id + domain，name 里含完整域名）

async fn create_txt_record(
    provider: &str,
    conf: &ProviderConf,
    name: &str,
    value: &str,
) -> Result<(String, String)> {
    match provider {
        "cloudflare" => {
            let token = &conf.api_token;
            if token.is_empty() {
                return Err(anyhow!("cloudflare: API Token 不能为空"));
            }
            cf_create_txt_record(token, &conf.zone_id, name, value).await
        }
        "alidns" => {
            if conf.access_key_id.is_empty() || conf.access_key_secret.is_empty() {
                return Err(anyhow!("alidns: AccessKeyId / AccessKeySecret 不能为空"));
            }
            alidns_create_txt_record(&conf.access_key_id, &conf.access_key_secret, name, value)
                .await
                .map(|record_id| (String::new(), record_id))
        }
        "tencentcloud" => {
            if conf.secret_id.is_empty() || conf.secret_key.is_empty() {
                return Err(anyhow!("tencentcloud: SecretId / SecretKey 不能为空"));
            }
            tencentcloud_create_txt_record(&conf.secret_id, &conf.secret_key, name, value)
                .await
                .map(|record_id| (String::new(), record_id))
        }
        other => Err(anyhow!("未知的 DNS 服务商: {}", other)),
    }
}

async fn cleanup_txt_records(
    provider: &str,
    conf: &ProviderConf,
    records: &[(String, String, String)],
) {
    match provider {
        "cloudflare" => cf_cleanup_txt_records(&conf.api_token, records).await,
        "alidns" => {
            alidns_cleanup_txt_records(&conf.access_key_id, &conf.access_key_secret, records)
                .await
        }
        "tencentcloud" => {
            tencentcloud_cleanup_txt_records(&conf.secret_id, &conf.secret_key, records).await
        }
        other => warn!("[tls] cleanup skipped: unknown DNS provider {}", other),
    }
}

// ─── Cloudflare DNS-01 ────────────────────────────────────────────────────────

async fn cf_resolve_zone(token: &str, zone_id_hint: &str, fqdn: &str) -> Result<String> {
    if !zone_id_hint.is_empty() {
        return Ok(zone_id_hint.to_string());
    }
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.cloudflare.com/client/v4/zones?per_page=100")
        .bearer_auth(token)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    let zones = resp["result"]
        .as_array()
        .ok_or_else(|| anyhow!("no zones"))?;
    let map: std::collections::HashMap<String, String> = zones
        .iter()
        .filter_map(|z| {
            Some((
                z["name"].as_str()?.to_string(),
                z["id"].as_str()?.to_string(),
            ))
        })
        .collect();
    let parts: Vec<&str> = fqdn.split('.').collect();
    for n in 2..=parts.len().min(20) {
        let candidate = parts[parts.len() - n..].join(".");
        if let Some(id) = map.get(&candidate) {
            return Ok(id.clone());
        }
    }
    Err(anyhow!("cloudflare: no zone found for {}", fqdn))
}

async fn cf_create_txt_record(
    token: &str,
    zone_id_hint: &str,
    name: &str,
    value: &str,
) -> Result<(String, String)> {
    let client = reqwest::Client::new();
    let zone_id = cf_resolve_zone(token, zone_id_hint, name).await?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
        zone_id
    );
    let body = serde_json::json!({"type": "TXT", "name": name, "content": value, "ttl": 60});
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    if resp["success"].as_bool() != Some(true) {
        let msg = resp["errors"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|e| e["message"].as_str())
            .unwrap_or("unknown");
        return Err(anyhow!("cloudflare create TXT: {}", msg));
    }
    let record_id = resp["result"]["id"]
        .as_str()
        .ok_or_else(|| anyhow!("no record id"))?
        .to_string();
    Ok((zone_id, record_id))
}

async fn cf_cleanup_txt_records(token: &str, records: &[(String, String, String)]) {
    let client = reqwest::Client::new();
    for (zone_id, record_id, name) in records {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        );
        match client.delete(&url).bearer_auth(token).send().await {
            Ok(_) => info!("[tls] deleted TXT record for {}", name),
            Err(e) => warn!("[tls] failed to delete TXT record for {}: {}", name, e),
        }
    }
}

// ─── AliDNS DNS-01 ────────────────────────────────────────────────────────────
//
// 阿里云公共 DNS API 2015-01-09，与 ddns.rs 中的实现共享同一套签名算法
// （HMAC-SHA1，RPC 风格参数签名）。TXT 记录的增删只是 Action 不同。

/// 从 FQDN 中拆出 (RR, DomainName)。
/// 例: "_acme-challenge.home.example.com" → ("_acme-challenge.home", "example.com")
fn tls_split_rr(fqdn: &str) -> (String, String) {
    let parts: Vec<&str> = fqdn.split('.').collect();
    if parts.len() <= 2 {
        return ("@".to_string(), fqdn.to_string());
    }
    // 取最后两段作为主域名，其余部分作为 RR（支持 _acme-challenge.sub 这种多级前缀）
    let domain = parts[parts.len() - 2..].join(".");
    let rr = parts[..parts.len() - 2].join(".");
    (rr, domain)
}

fn alidns_sign(key_secret: &str, string_to_sign: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;
    let signing_key = format!("{}&", key_secret);
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(string_to_sign.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn alidns_encode(s: &str) -> String {
    // 阿里云要求的百分号编码：比标准 URL 编码更严格（/ 也需转义）
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn alidns_call(
    client: &reqwest::Client,
    key_id: &str,
    key_secret: &str,
    action: &str,
    mut params: Vec<(&str, String)>,
) -> Result<serde_json::Value> {
    use chrono::Utc;
    use rand::RngCore;

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut nonce_bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    params.push(("Action", action.to_string()));
    params.push(("Format", "JSON".to_string()));
    params.push(("Version", "2015-01-09".to_string()));
    params.push(("AccessKeyId", key_id.to_string()));
    params.push(("SignatureMethod", "HMAC-SHA1".to_string()));
    params.push(("Timestamp", timestamp));
    params.push(("SignatureVersion", "1.0".to_string()));
    params.push(("SignatureNonce", nonce));

    params.sort_by(|a, b| a.0.cmp(b.0));

    let query_str: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", alidns_encode(k), alidns_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let string_to_sign = format!("GET&{}&{}", alidns_encode("/"), alidns_encode(&query_str));
    let signature = alidns_sign(key_secret, &string_to_sign);

    let url = format!(
        "https://alidns.aliyuncs.com/?{}&Signature={}",
        query_str,
        alidns_encode(&signature),
    );

    let resp = client
        .get(&url)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    if let Some(code) = resp.get("Code").and_then(|v| v.as_str()) {
        if code != "OK" {
            let msg = resp["Message"].as_str().unwrap_or(code);
            return Err(anyhow!("alidns error: {}", msg));
        }
    }
    Ok(resp)
}

async fn alidns_create_txt_record(
    key_id: &str,
    key_secret: &str,
    fqdn: &str,
    value: &str,
) -> Result<String> {
    let (rr, domain) = tls_split_rr(fqdn);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = alidns_call(
        &client,
        key_id,
        key_secret,
        "AddDomainRecord",
        vec![
            ("DomainName", domain),
            ("RR", rr),
            ("Type", "TXT".to_string()),
            ("Value", value.to_string()),
            ("TTL", "600".to_string()),
        ],
    )
    .await?;

    resp["RecordId"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("alidns: no RecordId in response"))
}

async fn alidns_cleanup_txt_records(
    key_id: &str,
    key_secret: &str,
    records: &[(String, String, String)],
) {
    if key_id.is_empty() || key_secret.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("[tls] alidns cleanup: failed to build client: {}", e);
            return;
        }
    };
    for (_, record_id, name) in records {
        match alidns_call(
            &client,
            key_id,
            key_secret,
            "DeleteDomainRecord",
            vec![("RecordId", record_id.clone())],
        )
        .await
        {
            Ok(_) => info!("[tls] deleted TXT record for {}", name),
            Err(e) => warn!("[tls] failed to delete TXT record for {}: {}", name, e),
        }
    }
}

// ─── TencentCloud DNS-01（DNSPod，TC3-HMAC-SHA256 签名）──────────────────────
//
// 文档: https://cloud.tencent.com/document/product/1427/56166
// Service: dnspod  Host: dnspod.tencentcloudapi.com
// 与 ddns.rs 中的实现共享同一套签名算法，仅 Action/参数不同。

fn tc3_sign(secret_key: &str, date: &str, service: &str, string_to_sign: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let sign_date = {
        let mut m = HmacSha256::new_from_slice(format!("TC3{}", secret_key).as_bytes()).unwrap();
        m.update(date.as_bytes());
        m.finalize().into_bytes()
    };
    let sign_service = {
        let mut m = HmacSha256::new_from_slice(&sign_date).unwrap();
        m.update(service.as_bytes());
        m.finalize().into_bytes()
    };
    let sign_request = {
        let mut m = HmacSha256::new_from_slice(&sign_service).unwrap();
        m.update(b"tc3_request");
        m.finalize().into_bytes()
    };
    let mut mac = HmacSha256::new_from_slice(&sign_request).unwrap();
    mac.update(string_to_sign.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

async fn tc3_call(
    client: &reqwest::Client,
    secret_id: &str,
    secret_key: &str,
    action: &str,
    body: &str,
) -> Result<serde_json::Value> {
    use chrono::Utc;
    use sha2::{Digest, Sha256};

    let service = "dnspod";
    let host = "dnspod.tencentcloudapi.com";
    let endpoint = format!("https://{}", host);
    let now = Utc::now();
    let timestamp = now.timestamp().to_string();
    let date = now.format("%Y-%m-%d").to_string();

    let hashed_body = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_headers = format!(
        "content-type:application/json\nhost:{}\nx-tc-action:{}\n",
        host,
        action.to_lowercase()
    );
    let signed_headers = "content-type;host;x-tc-action";
    let canonical_request = format!(
        "POST\n/\n\n{}\n{}\n{}",
        canonical_headers, signed_headers, hashed_body
    );

    let credential_scope = format!("{}/{}/tc3_request", date, service);
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, credential_scope, hashed_canonical
    );

    let signature = tc3_sign(secret_key, &date, service, &string_to_sign);

    let authorization = format!(
        "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        secret_id, credential_scope, signed_headers, signature
    );

    let resp = client
        .post(&endpoint)
        .header("Authorization", authorization)
        .header("Content-Type", "application/json")
        .header("Host", host)
        .header("X-TC-Action", action)
        .header("X-TC-Timestamp", &timestamp)
        .header("X-TC-Version", "2021-03-23")
        .body(body.to_string())
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(err) = resp.get("Response").and_then(|r| r.get("Error")) {
        let code = err["Code"].as_str().unwrap_or("Unknown");
        let msg = err["Message"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("tencentcloud dns error {}: {}", code, msg));
    }
    Ok(resp["Response"].clone())
}

async fn tencentcloud_create_txt_record(
    secret_id: &str,
    secret_key: &str,
    fqdn: &str,
    value: &str,
) -> Result<String> {
    let (sub_domain, domain) = tls_split_rr(fqdn);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let body = serde_json::json!({
        "Domain": domain,
        "SubDomain": sub_domain,
        "RecordType": "TXT",
        "RecordLine": "默认",
        "Value": value,
        "TTL": 600,
    })
    .to_string();

    let resp = tc3_call(&client, secret_id, secret_key, "CreateRecord", &body).await?;
    resp["RecordId"]
        .as_u64()
        .map(|id| id.to_string())
        .ok_or_else(|| anyhow!("tencentcloud: no RecordId in response"))
}

async fn tencentcloud_cleanup_txt_records(
    secret_id: &str,
    secret_key: &str,
    records: &[(String, String, String)],
) {
    if secret_id.is_empty() || secret_key.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("[tls] tencentcloud cleanup: failed to build client: {}", e);
            return;
        }
    };
    for (_, record_id, name) in records {
        let (_, domain) = tls_split_rr(name);
        let body = serde_json::json!({
            "Domain": domain,
            "RecordId": record_id.parse::<u64>().unwrap_or(0),
        })
        .to_string();
        match tc3_call(&client, secret_id, secret_key, "DeleteRecord", &body).await {
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
        .filter_map(|r| r.ok())
        .collect();
    let der = der_certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after = parsed.validity().not_after.to_datetime();
    let ts = not_after.unix_timestamp();
    // Format as RFC3339: YYYY-MM-DDTHH:MM:SSZ
    let secs_in_day = 86400i64;
    let days_since_epoch = ts / secs_in_day;
    let time_of_day = ts % secs_in_day;
    let (h, m, s) = (
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    );
    let (year, month, day) = approx_ymd(days_since_epoch);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    ))
}

fn approx_ymd(days: i64) -> (i64, i64, i64) {
    // Approximate gregorian calendar conversion
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let days_in_year = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days: [i64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1i64;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        month += 1;
    }
    (y, month, d + 1)
}

pub fn extract_domains_from_cert_pem(cert_pem: &str) -> Vec<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;
    let der_certs: Vec<_> = certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok())
        .collect();
    let Some(der) = der_certs.first() else {
        return vec![];
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der) else {
        return vec![];
    };

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
            if let Ok(s) = cn.as_str() {
                domains.insert(s.to_string());
            }
        }
    }
    domains.into_iter().collect()
}

// ─── Base64url decode（无 padding，支持 - _ 字符）─────────────────────────────
// ZeroSSL 下发的 HMAC Key 是 Base64url 格式（RFC 4648 §5，无 padding）。
// instant-acme ExternalAccountKey::new 接受原始字节，需要先解码。
fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine as _};

    // 先尝试无 padding 的 Base64url
    if let Ok(raw) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(raw);
    }
    // 补 padding 后再试
    let pad = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.to_string(),
    };
    if let Ok(raw) = general_purpose::URL_SAFE.decode(&pad) {
        return Ok(raw);
    }
    // 最后尝试标准 Base64
    general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow!("base64 decode: {}", e))
}

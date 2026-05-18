//! ACME certificate issuance via instant-acme.
//! Supports HTTP-01 and DNS-01 challenges.
//! DNS-01 is required for wildcard certs and matches Go version's capability.

use anyhow::{anyhow, Context};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::time::Duration;
use tokio::time::sleep;

use crate::models::TlsRule;
use crate::state::now_rfc3339;

/// Issue (or renew) a TLS certificate using ACME DNS-01 or HTTP-01.
/// Returns (cert_pem, key_pem, issued_at, expires_at).
pub async fn issue_cert(rule: &TlsRule) -> anyhow::Result<(String, String, String, String)> {
    let domains = effective_domains(rule);
    if domains.is_empty() {
        return Err(anyhow!("no domains configured"));
    }

    // Decide challenge type: use DNS-01 if provider is configured (required for wildcards)
    let use_dns01 = !rule.provider.is_empty()
        || domains.iter().any(|d| d.starts_with("*."));

    let email = if rule.email.is_empty() {
        return Err(anyhow!("email is required for ACME"));
    } else {
        rule.email.clone()
    };

    // Select ACME directory
    let directory = match rule.ca_provider.to_lowercase().as_str() {
        "zerossl" => "https://acme.zerossl.com/v2/DV90".to_string(),
        "buypass" => "https://api.buypass.com/acme/directory".to_string(),
        _ => LetsEncrypt::Production.url().to_string(),
    };

    let new_account = NewAccount {
        contact: &[&format!("mailto:{email}")],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    // ZeroSSL requires External Account Binding (EAB)
    let eab = if rule.ca_provider.to_lowercase() == "zerossl"
        && !rule.provider_conf.zerossl_api_key.is_empty()
        && !rule.provider_conf.zerossl_key_id.is_empty()
    {
        // Decode ZeroSSL HMAC key (base64url → raw bytes)
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&rule.provider_conf.zerossl_api_key)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&rule.provider_conf.zerossl_api_key))
            .context("decode ZeroSSL HMAC key")?;
        Some((rule.provider_conf.zerossl_key_id.clone(), raw))
    } else {
        None
    };

    // instant-acme 0.7.2: ExternalAccountKey<'a> { id: &'a str, key: &'a [u8] }
    // We keep the raw bytes in an owned variable so references stay valid
    let eab_bytes: Option<(String, Vec<u8>)> = eab;
    let eab_key: Option<instant_acme::ExternalAccountKey<'_>> = eab_bytes
        .as_ref()
        .map(|(kid, raw_bytes)| instant_acme::ExternalAccountKey {
            id: kid.as_str(),
            key: raw_bytes.as_slice(),
        });

    let (account, _) = Account::create(&new_account, &directory, eab_key.as_ref())
        .await
        .context("create ACME account")?;

    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder { identifiers: &identifiers })
        .await
        .context("new ACME order")?;

    let authorizations = order.authorizations().await.context("get authorizations")?;

    let challenge_type = if use_dns01 { ChallengeType::Dns01 } else { ChallengeType::Http01 };

    // Collect all DNS TXT records needed
    let mut dns_records: Vec<(String, String)> = vec![];

    for auth in &authorizations {
        let challenge = auth.challenges.iter()
            .find(|c| c.r#type == challenge_type)
            .or_else(|| auth.challenges.iter().find(|c| c.r#type == ChallengeType::Dns01))
            .or_else(|| auth.challenges.first())
            .ok_or_else(|| anyhow!("no suitable ACME challenge found"))?;

        if challenge.r#type == ChallengeType::Dns01 {
            let key_auth = order.key_authorization(challenge);
            let digest = key_auth.dns_value();
            // For DNS-01, TXT record goes at _acme-challenge.<domain>
            let ident_domain = match &auth.identifier {
                Identifier::Dns(d) => d.clone(),
            };
            let record_name = format!("_acme-challenge.{ident_domain}");
            dns_records.push((record_name, digest.to_string()));
        }
    }

    if !dns_records.is_empty() {
        // Set all DNS TXT records
        for (rec_name, txt_value) in &dns_records {
            eprintln!("[acme] DNS-01: set TXT {rec_name} = {txt_value}");
            set_dns_txt_record(rule, rec_name, txt_value).await?;
        }
        // Wait for DNS propagation (Go version uses 30s)
        eprintln!("[acme] waiting 30s for DNS propagation...");
        sleep(Duration::from_secs(30)).await;
    }

    // Notify ACME server that challenges are ready
    for auth in &authorizations {
        let challenge = auth.challenges.iter()
            .find(|c| c.r#type == challenge_type)
            .or_else(|| auth.challenges.iter().find(|c| c.r#type == ChallengeType::Dns01))
            .or_else(|| auth.challenges.first())
            .ok_or_else(|| anyhow!("no challenge"))?;
        order.set_challenge_ready(&challenge.url).await?;
    }

    // Poll for order ready (max 2 minutes)
    let mut attempts = 0;
    loop {
        sleep(Duration::from_secs(6)).await;
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                return Err(anyhow!("ACME order invalid — check DNS records or challenge setup"));
            }
            OrderStatus::Valid => break,
            _ => {}
        }
        attempts += 1;
        if attempts > 20 {
            return Err(anyhow!("ACME order timed out after {}s", attempts * 6));
        }
    }

    // Generate key pair and CSR
    let mut params = CertificateParams::new(domains.clone())
        .map_err(|e| anyhow!("cert params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().map_err(|e| anyhow!("keygen: {e}"))?;
    let csr = params.serialize_request(&key_pair).map_err(|e| anyhow!("csr: {e}"))?;

    // Finalize
    order.finalize(csr.der()).await.context("finalize ACME order")?;

    // Poll for certificate
    let mut cert_chain = None;
    for _ in 0..20 {
        sleep(Duration::from_secs(5)).await;
        if let Some(chain) = order.certificate().await? {
            cert_chain = Some(chain);
            break;
        }
    }

    let cert_pem = cert_chain.ok_or_else(|| anyhow!("certificate not available after polling"))?;
    let key_pem = key_pair.serialize_pem();
    let issued_at = now_rfc3339();
    let expires_at = parse_expiry_from_pem(&cert_pem).unwrap_or_default();

    // Clean up DNS TXT records (best effort)
    for (rec_name, _) in &dns_records {
        let _ = delete_dns_txt_record(rule, rec_name).await;
    }

    Ok((cert_pem, key_pem, issued_at, expires_at))
}

/// Set DNS TXT record for DNS-01 challenge via the configured DNS provider.
async fn set_dns_txt_record(rule: &TlsRule, record_name: &str, value: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => dns01_cloudflare_set(&client, rule, record_name, value).await,
        "alidns" | "aliyun" => dns01_alidns_set(&client, rule, record_name, value).await,
        "dnspod" => dns01_dnspod_set(&client, rule, record_name, value).await,
        "tencent" | "tencentcloud" => dns01_tencent_set(&client, rule, record_name, value).await,
        p => {
            eprintln!("[acme] unknown DNS provider {p:?}, DNS-01 challenge may fail");
            Ok(())
        }
    }
}

/// Delete DNS TXT record after challenge.
async fn delete_dns_txt_record(rule: &TlsRule, record_name: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => dns01_cloudflare_delete(&client, rule, record_name).await,
        "alidns" | "aliyun" => dns01_alidns_delete(&client, rule, record_name).await,
        "dnspod" => dns01_dnspod_delete(&client, rule, record_name).await,
        "tencent" | "tencentcloud" => dns01_tencent_delete(&client, rule, record_name).await,
        _ => Ok(()),
    }
}

// ─── Cloudflare DNS-01 ────────────────────────────────────────────────────────

async fn dns01_cloudflare_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;
    if token.is_empty() || zone.is_empty() {
        return Err(anyhow!("Cloudflare requires api_token and zone_id"));
    }

    // Delete any existing TXT records first
    let _ = dns01_cloudflare_delete(client, rule, record_name).await;

    let resp: serde_json::Value = client
        .post(format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120
        }))
        .send()
        .await?
        .json()
        .await?;

    if !resp["success"].as_bool().unwrap_or(false) {
        return Err(anyhow!("Cloudflare set TXT failed: {}", resp["errors"]));
    }
    Ok(())
}

async fn dns01_cloudflare_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;

    let resp: serde_json::Value = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={record_name}"
        ))
        .bearer_auth(token)
        .send()
        .await?
        .json()
        .await?;

    if let Some(records) = resp["result"].as_array() {
        for rec in records {
            if let Some(rid) = rec["id"].as_str() {
                let _ = client
                    .delete(format!(
                        "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rid}"
                    ))
                    .bearer_auth(token)
                    .send()
                    .await;
            }
        }
    }
    Ok(())
}

// ─── AliDNS DNS-01 ────────────────────────────────────────────────────────────

async fn dns01_alidns_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;

    let (rr, domain) = split_record_name(record_name);

    // Delete existing first
    let _ = dns01_alidns_delete(client, rule, record_name).await;

    let params = crate::engines::build_aliyun_params(key_id, "AddDomainRecord", &[
        ("DomainName", domain), ("RR", rr), ("Type", "TXT"), ("Value", value), ("TTL", "120"),
    ]);
    let signed = crate::engines::sign_aliyun_params(&params, key_secret);

    client.get("https://alidns.aliyuncs.com/")
        .query(&signed)
        .send().await?;

    Ok(())
}

async fn dns01_alidns_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
) -> anyhow::Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    let (rr, domain) = split_record_name(record_name);

    let list_params = crate::engines::build_aliyun_params(key_id, "DescribeDomainRecords", &[
        ("DomainName", domain), ("RRKeyWord", rr), ("TypeKeyWord", "TXT"),
    ]);
    let signed = crate::engines::sign_aliyun_params(&list_params, key_secret);

    let resp: serde_json::Value = client
        .get("https://alidns.aliyuncs.com/").query(&signed)
        .send().await?.json().await?;

    if let Some(records) = resp["DomainRecords"]["Record"].as_array() {
        for rec in records {
            if let Some(rid) = rec["RecordId"].as_str() {
                let del_params = crate::engines::build_aliyun_params(key_id, "DeleteDomainRecord", &[
                    ("RecordId", rid),
                ]);
                let signed_del = crate::engines::sign_aliyun_params(&del_params, key_secret);
                let _ = client.get("https://alidns.aliyuncs.com/").query(&signed_del).send().await;
            }
        }
    }
    Ok(())
}

// ─── DNSPod DNS-01 ────────────────────────────────────────────────────────────

async fn dns01_dnspod_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let (sub, domain) = split_record_name(record_name);

    // Delete existing first
    let _ = dns01_dnspod_delete(client, rule, record_name).await;

    client.post("https://dnsapi.cn/Record.Create")
        .form(&[("login_token", token.as_str()), ("format", "json"),
                ("domain", domain), ("sub_domain", sub),
                ("record_type", "TXT"), ("value", value),
                ("record_line", "默认"), ("ttl", "120")])
        .send().await?;
    Ok(())
}

async fn dns01_dnspod_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let (sub, domain) = split_record_name(record_name);

    let list: serde_json::Value = client
        .post("https://dnsapi.cn/Record.List")
        .form(&[("login_token", token.as_str()), ("format", "json"),
                ("domain", domain), ("sub_domain", sub)])
        .send().await?.json().await?;

    if let Some(records) = list["records"].as_array() {
        for rec in records {
            if rec["type"].as_str() == Some("TXT") {
                if let Some(rid) = rec["id"].as_str() {
                    let _ = client.post("https://dnsapi.cn/Record.Remove")
                        .form(&[("login_token", token.as_str()), ("format", "json"),
                                ("domain", domain), ("record_id", rid)])
                        .send().await;
                }
            }
        }
    }
    Ok(())
}

async fn dns01_tencent_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    let token = format!("{secret_id},{secret_key}");
    let mut proxy = rule.clone();
    proxy.provider_conf.api_token = token;
    dns01_dnspod_set(client, &proxy, record_name, value).await
}

async fn dns01_tencent_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    record_name: &str,
) -> anyhow::Result<()> {
    let secret_id = &rule.provider_conf.secret_id;
    let secret_key = &rule.provider_conf.secret_key;
    let token = format!("{secret_id},{secret_key}");
    let mut proxy = rule.clone();
    proxy.provider_conf.api_token = token;
    dns01_dnspod_delete(client, &proxy, record_name).await
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Split "_acme-challenge.sub.example.com" into ("_acme-challenge.sub", "example.com")
fn split_record_name(record_name: &str) -> (&str, &str) {
    // Split "_acme-challenge.sub.example.com" -> ("_acme-challenge.sub", "example.com")
    let parts: Vec<&str> = record_name.split('.').collect();
    if parts.len() >= 3 {
        // domain = last 2 parts
        let domain_len = parts[parts.len() - 2].len() + 1 + parts[parts.len() - 1].len();
        let rr = &record_name[..record_name.len() - domain_len - 1];
        let domain = &record_name[rr.len() + 1..];
        if !rr.is_empty() { return (rr, domain); }
    } else if parts.len() == 2 {
        return ("@", record_name);
    }
    ("@", record_name)
}

pub fn effective_domains(rule: &TlsRule) -> Vec<String> {
    if !rule.domains.is_empty() { return rule.domains.clone(); }
    if !rule.domain.is_empty() { return vec![rule.domain.clone()]; }
    vec![]
}

fn parse_expiry_from_pem(pem_chain: &str) -> Option<String> {
    use base64::Engine;
    // Only look at first cert block
    let start = pem_chain.find("-----BEGIN CERTIFICATE-----")?;
    let end = pem_chain[start..].find("-----END CERTIFICATE-----")? + start + 25;
    let block = &pem_chain[start..=end];
    let b64: String = block.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
    let der = base64::engine::general_purpose::STANDARD.decode(&b64).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    let dt = chrono::DateTime::from_timestamp(ts, 0)?;
    Some(dt.to_rfc3339())
}

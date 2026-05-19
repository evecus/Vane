//! ACME certificate issuance via instant-acme.
//! Supports HTTP-01 and DNS-01 challenges.
//! DNS-01 is required for wildcard certs.

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

    let email = if rule.email.is_empty() {
        return Err(anyhow!("email is required for ACME"));
    } else {
        rule.email.clone()
    };

    // Select ACME directory URL
    let directory = match rule.ca_provider.to_lowercase().as_str() {
        "zerossl" => instant_acme::ZeroSsl::Production.url().to_string(),
        "buypass" => "https://api.buypass.com/acme/directory".to_string(),
        _ => LetsEncrypt::Production.url().to_string(),
    };

    let new_account = NewAccount {
        contact: &[&format!("mailto:{email}")],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, _) = Account::create(&new_account, &directory, None)
        .await
        .context("create ACME account")?;

    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .context("new ACME order")?;

    let authorizations = order.authorizations().await.context("get authorizations")?;

    // Use DNS-01 if provider is configured (required for wildcards), else HTTP-01
    let use_dns01 = !rule.provider.is_empty() || domains.iter().any(|d| d.starts_with("*."));
    let preferred = if use_dns01 {
        ChallengeType::Dns01
    } else {
        ChallengeType::Http01
    };

    // Collect DNS TXT records needed for DNS-01
    let mut dns_records: Vec<(String, String)> = vec![];

    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == preferred)
            .or_else(|| {
                auth.challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Dns01)
            })
            .or_else(|| auth.challenges.first())
            .ok_or_else(|| anyhow!("no suitable ACME challenge found"))?;

        if challenge.r#type == ChallengeType::Dns01 {
            let key_auth = order.key_authorization(challenge);
            let digest = key_auth.dns_value();
            let ident_domain = match &auth.identifier {
                Identifier::Dns(d) => d.clone(),
            };
            let record_name = format!("_acme-challenge.{ident_domain}");
            dns_records.push((record_name, digest.to_string()));
        }
    }

    if !dns_records.is_empty() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        for (rec_name, txt_value) in &dns_records {
            eprintln!("[acme] DNS-01: set TXT {rec_name} = {txt_value}");
            set_dns_txt_record(&client, rule, rec_name, txt_value).await?;
        }
        eprintln!("[acme] waiting 30s for DNS propagation...");
        sleep(Duration::from_secs(30)).await;
    }

    // Notify ACME server challenges are ready
    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == preferred)
            .or_else(|| {
                auth.challenges
                    .iter()
                    .find(|c| c.r#type == ChallengeType::Dns01)
            })
            .or_else(|| auth.challenges.first())
            .ok_or_else(|| anyhow!("no challenge"))?;
        order.set_challenge_ready(&challenge.url).await?;
    }

    // Poll for order ready (max ~2 minutes)
    let mut attempts = 0;
    loop {
        sleep(Duration::from_secs(6)).await;
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid => {
                return Err(anyhow!(
                    "ACME order invalid — check DNS records or challenge setup"
                ));
            }
            _ => {}
        }
        attempts += 1;
        if attempts > 20 {
            return Err(anyhow!("ACME order timed out after {}s", attempts * 6));
        }
    }

    // Generate key pair and CSR
    let mut params =
        CertificateParams::new(domains.clone()).map_err(|e| anyhow!("cert params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().map_err(|e| anyhow!("keygen: {e}"))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| anyhow!("csr: {e}"))?;

    order
        .finalize(csr.der())
        .await
        .context("finalize ACME order")?;

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
    if !dns_records.is_empty() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        for (rec_name, _) in &dns_records {
            let _ = delete_dns_txt_record(&client, rule, rec_name).await;
        }
    }

    Ok((cert_pem, key_pem, issued_at, expires_at))
}

// ─── DNS-01 provider dispatch ─────────────────────────────────────────────────

async fn set_dns_txt_record(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => dns01_cloudflare_set(client, rule, name, value).await,
        "alidns" | "aliyun" => dns01_alidns_set(client, rule, name, value).await,
        "dnspod" => dns01_dnspod_set(client, rule, name, value).await,
        "tencent" | "tencentcloud" => dns01_tencent_set(client, rule, name, value).await,
        p => {
            eprintln!("[acme] unknown DNS provider {p:?}");
            Ok(())
        }
    }
}

async fn delete_dns_txt_record(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
) -> anyhow::Result<()> {
    match rule.provider.to_lowercase().as_str() {
        "cloudflare" => dns01_cloudflare_delete(client, rule, name).await,
        "alidns" | "aliyun" => dns01_alidns_delete(client, rule, name).await,
        "dnspod" => dns01_dnspod_delete(client, rule, name).await,
        "tencent" | "tencentcloud" => dns01_tencent_delete(client, rule, name).await,
        _ => Ok(()),
    }
}

// ─── Cloudflare ───────────────────────────────────────────────────────────────

async fn dns01_cloudflare_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;
    if token.is_empty() || zone.is_empty() {
        return Err(anyhow!("Cloudflare requires api_token and zone_id"));
    }
    let _ = dns01_cloudflare_delete(client, rule, name).await;
    let resp: serde_json::Value = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"
        ))
        .bearer_auth(token)
        .json(&serde_json::json!({"type":"TXT","name":name,"content":value,"ttl":120}))
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
    name: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let zone = &rule.provider_conf.zone_id;
    let resp: serde_json::Value = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone}/dns_records?type=TXT&name={name}"
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

// ─── AliDNS ───────────────────────────────────────────────────────────────────

async fn dns01_alidns_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    let (rr, domain) = split_record_name(name);
    let _ = dns01_alidns_delete(client, rule, name).await;
    let params = crate::engines::build_aliyun_params(
        key_id,
        "AddDomainRecord",
        &[
            ("DomainName", domain),
            ("RR", rr),
            ("Type", "TXT"),
            ("Value", value),
            ("TTL", "120"),
        ],
    );
    let signed = crate::engines::sign_aliyun_params(&params, key_secret);
    client
        .get("https://alidns.aliyuncs.com/")
        .query(&signed)
        .send()
        .await?;
    Ok(())
}

async fn dns01_alidns_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
) -> anyhow::Result<()> {
    let key_id = &rule.provider_conf.access_key_id;
    let key_secret = &rule.provider_conf.access_key_secret;
    let (rr, domain) = split_record_name(name);
    let params = crate::engines::build_aliyun_params(
        key_id,
        "DescribeDomainRecords",
        &[
            ("DomainName", domain),
            ("RRKeyWord", rr),
            ("TypeKeyWord", "TXT"),
        ],
    );
    let resp: serde_json::Value = client
        .get("https://alidns.aliyuncs.com/")
        .query(&crate::engines::sign_aliyun_params(&params, key_secret))
        .send()
        .await?
        .json()
        .await?;
    if let Some(records) = resp["DomainRecords"]["Record"].as_array() {
        for rec in records {
            if let Some(rid) = rec["RecordId"].as_str() {
                let del = crate::engines::build_aliyun_params(
                    key_id,
                    "DeleteDomainRecord",
                    &[("RecordId", rid)],
                );
                let _ = client
                    .get("https://alidns.aliyuncs.com/")
                    .query(&crate::engines::sign_aliyun_params(&del, key_secret))
                    .send()
                    .await;
            }
        }
    }
    Ok(())
}

// ─── DNSPod ───────────────────────────────────────────────────────────────────

async fn dns01_dnspod_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let (sub, domain) = split_record_name(name);
    let _ = dns01_dnspod_delete(client, rule, name).await;
    client
        .post("https://dnsapi.cn/Record.Create")
        .form(&[
            ("login_token", token.as_str()),
            ("format", "json"),
            ("domain", domain),
            ("sub_domain", sub),
            ("record_type", "TXT"),
            ("value", value),
            ("record_line", "默认"),
            ("ttl", "120"),
        ])
        .send()
        .await?;
    Ok(())
}

async fn dns01_dnspod_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
) -> anyhow::Result<()> {
    let token = &rule.provider_conf.api_token;
    let (sub, domain) = split_record_name(name);
    let list: serde_json::Value = client
        .post("https://dnsapi.cn/Record.List")
        .form(&[
            ("login_token", token.as_str()),
            ("format", "json"),
            ("domain", domain),
            ("sub_domain", sub),
        ])
        .send()
        .await?
        .json()
        .await?;
    if let Some(records) = list["records"].as_array() {
        for rec in records {
            if rec["type"].as_str() == Some("TXT") {
                if let Some(rid) = rec["id"].as_str() {
                    let _ = client
                        .post("https://dnsapi.cn/Record.Remove")
                        .form(&[
                            ("login_token", token.as_str()),
                            ("format", "json"),
                            ("domain", domain),
                            ("record_id", rid),
                        ])
                        .send()
                        .await;
                }
            }
        }
    }
    Ok(())
}

async fn dns01_tencent_set(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
    value: &str,
) -> anyhow::Result<()> {
    let token = format!(
        "{},{}",
        rule.provider_conf.secret_id, rule.provider_conf.secret_key
    );
    let mut proxy = rule.clone();
    proxy.provider_conf.api_token = token;
    dns01_dnspod_set(client, &proxy, name, value).await
}

async fn dns01_tencent_delete(
    client: &reqwest::Client,
    rule: &TlsRule,
    name: &str,
) -> anyhow::Result<()> {
    let token = format!(
        "{},{}",
        rule.provider_conf.secret_id, rule.provider_conf.secret_key
    );
    let mut proxy = rule.clone();
    proxy.provider_conf.api_token = token;
    dns01_dnspod_delete(client, &proxy, name).await
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Split "_acme-challenge.sub.example.com" -> ("_acme-challenge.sub", "example.com")
fn split_record_name(record_name: &str) -> (&str, &str) {
    let parts: Vec<&str> = record_name.split('.').collect();
    if parts.len() >= 3 {
        let domain_len = parts[parts.len() - 2].len() + 1 + parts[parts.len() - 1].len();
        let rr = &record_name[..record_name.len() - domain_len - 1];
        let domain = &record_name[rr.len() + 1..];
        if !rr.is_empty() {
            return (rr, domain);
        }
    } else if parts.len() == 2 {
        return ("@", record_name);
    }
    ("@", record_name)
}

pub fn effective_domains(rule: &TlsRule) -> Vec<String> {
    if !rule.domains.is_empty() {
        return rule.domains.clone();
    }
    if !rule.domain.is_empty() {
        return vec![rule.domain.clone()];
    }
    vec![]
}

fn parse_expiry_from_pem(pem_chain: &str) -> Option<String> {
    use base64::Engine;
    let start = pem_chain.find("-----BEGIN CERTIFICATE-----")?;
    let chunk = &pem_chain[start..];
    let end = chunk.find("-----END CERTIFICATE-----")? + 25;
    let block = &chunk[..end];
    let b64: String = block
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let ts = cert.validity().not_after.timestamp();
    let dt = chrono::DateTime::from_timestamp(ts, 0)?;
    Some(dt.to_rfc3339())
}

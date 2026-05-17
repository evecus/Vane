//! ACME certificate issuance via instant-acme (Let's Encrypt / ZeroSSL / Buypass).
//! Supports HTTP-01 challenge only for now.

use anyhow::{anyhow, Context};
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};

use crate::models::TlsRule;
use crate::state::now_rfc3339;

/// Issue (or renew) a TLS certificate using ACME.
/// Returns (cert_pem, key_pem, issued_at, expires_at).
pub async fn issue_cert(cert: &TlsRule) -> anyhow::Result<(String, String, String, String)> {
    let domains = effective_domains(cert);
    if domains.is_empty() {
        return Err(anyhow!("no domains configured"));
    }

    let email = if cert.email.is_empty() {
        return Err(anyhow!("email is required for ACME"));
    } else {
        cert.email.clone()
    };

    // Select ACME directory
    let directory = match cert.ca_provider.to_lowercase().as_str() {
        "zerossl" => instant_acme::ZeroSsl::Production
            .url()
            .to_string(),
        "buypass" => "https://api.buypass.com/acme/directory".to_string(),
        _ => LetsEncrypt::Production.url().to_string(),
    };

    // Create or restore account
    let new_account = NewAccount {
        contact: &[&format!("mailto:{email}")],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (account, _) = Account::create(&new_account, &directory, None)
        .await
        .context("create ACME account")?;

    // Place order
    let identifiers: Vec<Identifier> = domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .context("new ACME order")?;

    let authorizations = order.authorizations().await.context("get authorizations")?;
    let mut challenges = vec![];

    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("no HTTP-01 challenge available"))?;

        let token = challenge.token.clone();
        let key_auth = order.key_authorization(challenge);
        challenges.push((token, key_auth.as_str().to_string()));
    }

    // NOTE: For HTTP-01 challenges the caller/engine must serve the challenge
    // token at /.well-known/acme-challenge/<token> with the key_authorization
    // as the response body. In production this would be integrated into the
    // web service engine.  For now we log what would be needed.
    for (token, ka) in &challenges {
        eprintln!("[acme] HTTP-01 challenge: token={token}, key_auth={ka}");
        eprintln!("[acme] Serve GET /.well-known/acme-challenge/{token} -> {ka}");
    }

    // Set challenges ready
    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("no HTTP-01 challenge"))?;
        order.set_challenge_ready(&challenge.url).await?;
    }

    // Poll for order ready
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => return Err(anyhow!("ACME order invalid")),
            _ => {}
        }
        attempts += 1;
        if attempts > 20 {
            return Err(anyhow!("ACME order timed out"));
        }
    }

    // Generate CSR
    let mut params = CertificateParams::new(domains.clone())
        .map_err(|e| anyhow!("cert params: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let key_pair = KeyPair::generate().map_err(|e| anyhow!("keygen: {e}"))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| anyhow!("csr: {e}"))?;

    // Finalize order
    order.finalize(csr.der()).await.context("finalize order")?;

    // Poll for certificate
    let mut cert_pem_chain = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Some(cert_chain) = order.certificate().await? {
            cert_pem_chain = Some(cert_chain);
            break;
        }
    }

    let cert_chain =
        cert_pem_chain.ok_or_else(|| anyhow!("ACME certificate not available after polling"))?;
    let key_pem = key_pair.serialize_pem();
    let issued_at = now_rfc3339();

    // Parse expiry from first cert block
    let expires_at = parse_expiry(&cert_chain).unwrap_or_default();

    Ok((cert_chain, key_pem, issued_at, expires_at))
}

fn effective_domains(rule: &TlsRule) -> Vec<String> {
    if !rule.domains.is_empty() {
        return rule.domains.clone();
    }
    if !rule.domain.is_empty() {
        return vec![rule.domain.clone()];
    }
    vec![]
}

fn parse_expiry(pem_chain: &str) -> Option<String> {
    use base64::Engine;
    let b64: String = pem_chain
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD.decode(&b64).ok()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let not_after = cert.validity().not_after;
    let ts = chrono::DateTime::from_timestamp(not_after.timestamp(), 0)?;
    Some(ts.to_rfc3339())
}

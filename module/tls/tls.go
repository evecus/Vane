package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	cf "github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/yourusername/vane/config"
)

// ACME CA directory URLs
const (
	CALetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"
	CAZeroSSL     = "https://acme.zerossl.com/v2/DV90"
)

// Manager handles certificate issuance and auto-renewal.
type Manager struct {
	cfg *config.Config

	// inFlight tracks cert IDs currently being issued to prevent duplicate concurrent requests.
	inFlightMu sync.Mutex
	inFlight   map[string]struct{}
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:      cfg,
		inFlight: make(map[string]struct{}),
	}
}

// StartAutoRenew launches a background goroutine that checks for expiring certs every 12 hours.
func (m *Manager) StartAutoRenew() {
	go func() {
		// Run once at startup (after a short delay to let services stabilize)
		time.Sleep(30 * time.Second)
		m.renewAll()

		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			m.renewAll()
		}
	}()
}

func (m *Manager) renewAll() {
	m.cfg.RLock()
	certs := make([]config.TLSCert, len(m.cfg.TLSCerts))
	copy(certs, m.cfg.TLSCerts)
	m.cfg.RUnlock()

	for _, c := range certs {
		if !c.AutoRenew || c.Source != "acme" {
			continue
		}
		// Skip if already in error state and renewal failed recently
		if c.Status == "error" {
			continue
		}
		days := c.DaysUntilExpiry()
		// Renew when ≤30 days remain, or if status is pending/never issued
		if days > 30 && c.Status == "active" {
			continue
		}
		if days < 0 && c.CertPEM != "" && c.Status == "active" {
			// Already expired — force renew
		}
		log.Printf("[tls] auto-renew: cert %q expires in %d days, renewing...", c.Domain, days)
		if err := m.IssueCert(c.ID); err != nil {
			log.Printf("[tls] auto-renew: cert %q failed: %v", c.Domain, err)
		} else {
			log.Printf("[tls] auto-renew: cert %q renewed successfully", c.Domain)
		}
	}
}

// IssueCert triggers ACME DNS-01 certificate issuance for a cert config.
// It is safe to call concurrently — duplicate calls for the same ID are de-duplicated.
func (m *Manager) IssueCert(certID string) error {
	// De-duplicate in-flight requests
	m.inFlightMu.Lock()
	if _, busy := m.inFlight[certID]; busy {
		m.inFlightMu.Unlock()
		return fmt.Errorf("certificate issuance already in progress for %s", certID)
	}
	m.inFlight[certID] = struct{}{}
	m.inFlightMu.Unlock()
	defer func() {
		m.inFlightMu.Lock()
		delete(m.inFlight, certID)
		m.inFlightMu.Unlock()
	}()

	// Load cert config
	m.cfg.RLock()
	var cert *config.TLSCert
	for i := range m.cfg.TLSCerts {
		if m.cfg.TLSCerts[i].ID == certID {
			c := m.cfg.TLSCerts[i]
			cert = &c
			break
		}
	}
	m.cfg.RUnlock()
	if cert == nil {
		return fmt.Errorf("cert %s not found", certID)
	}

	log.Printf("[tls] IssueCert start: id=%s ca=%q domains=%v", certID, cert.CAProvider, cert.Domains)

	// Validate required fields before issuing
	if cert.Email == "" {
		return fmt.Errorf("email address is required for ACME certificate issuance")
	}
	domains := cert.Domains
	if len(domains) == 0 && cert.Domain != "" {
		domains = []string{cert.Domain}
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains specified for cert %s", certID)
	}

	// Generate a fresh ECDSA P-256 account key for each issuance
	// (lego recommends separate account keys per registration)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate account key: %w", err)
	}

	user := &acmeUser{email: cert.Email, key: privKey}
	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// Select CA
	switch cert.CAProvider {
	case "zerossl":
		legoConfig.CADirURL = CAZeroSSL
	default:
		legoConfig.CADirURL = CALetsEncrypt
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("create ACME client: %w", err)
	}

	// Configure DNS challenge provider
	if err := setupDNSProvider(client, cert); err != nil {
		return fmt.Errorf("configure DNS provider: %w", err)
	}

	// Register ACME account
	var reg *registration.Resource
	if cert.CAProvider == "zerossl" && cert.ProviderConf.ZeroSSLAPIKey != "" && cert.ProviderConf.ZeroSSLKeyID != "" {
		log.Printf("[tls] registering ZeroSSL EAB account for cert %s", certID)
		// ZeroSSL 返回的 HMAC Key 是 Base64url 无 padding 格式。
		// lego 的 HmacEncoded 字段内部用标准 Base64 解码，需先做格式转换。
		hmac := normalizeBase64(cert.ProviderConf.ZeroSSLAPIKey)
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  cert.ProviderConf.ZeroSSLKeyID,
			HmacEncoded:          hmac,
		})
	} else {
		if cert.CAProvider == "zerossl" {
			log.Printf("[tls] WARNING: ZeroSSL selected but EAB credentials missing; falling back to standard registration")
		}
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if err != nil {
		return fmt.Errorf("register ACME account: %w", err)
	}
	if err != nil {
		return fmt.Errorf("register ACME account: %w", err)
	}
	user.registration = reg

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain certificate: %w", err)
	}

	// Validate the returned certificate
	if err := validateCertKeyPair(certificates.Certificate, certificates.PrivateKey); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	expiresAt := parseCertExpiry(certificates.Certificate)
	log.Printf("[tls] certificate obtained for %v, expires %s", domains, expiresAt)

	// Persist to DB
	m.cfg.Lock()
	for i := range m.cfg.TLSCerts {
		if m.cfg.TLSCerts[i].ID == certID {
			m.cfg.TLSCerts[i].CertPEM = string(certificates.Certificate)
			m.cfg.TLSCerts[i].KeyPEM = string(certificates.PrivateKey)
			m.cfg.TLSCerts[i].IssuedAt = config.Now()
			m.cfg.TLSCerts[i].ExpiresAt = expiresAt
			m.cfg.TLSCerts[i].Status = "active"
			m.cfg.TLSCerts[i].ErrorMsg = ""
			if len(m.cfg.TLSCerts[i].Domains) > 0 {
				m.cfg.TLSCerts[i].Domain = m.cfg.TLSCerts[i].Domains[0]
			}
			break
		}
	}
	m.cfg.Unlock()

	// Reload in-memory state from DB after save
	if err := m.cfg.SaveTLSCert(m.getInMemoryCert(certID)); err != nil {
		return fmt.Errorf("persist certificate: %w", err)
	}
	return nil
}

// getInMemoryCert returns a copy of the in-memory cert by ID (must be called without lock).
func (m *Manager) getInMemoryCert(certID string) config.TLSCert {
	m.cfg.RLock()
	defer m.cfg.RUnlock()
	for _, c := range m.cfg.TLSCerts {
		if c.ID == certID {
			return c
		}
	}
	return config.TLSCert{}
}

// setupDNSProvider configures the DNS-01 challenge provider for the given cert.
func setupDNSProvider(client *lego.Client, cert *config.TLSCert) error {
	switch cert.Provider {
	case "cloudflare":
		cfCfg := cf.NewDefaultConfig()
		cfCfg.AuthToken = cert.ProviderConf.APIToken
		// Generous timeouts to handle slow DNS propagation
		cfCfg.PropagationTimeout = 10 * time.Minute
		cfCfg.PollingInterval = 15 * time.Second
		provider, err := cf.NewDNSProviderConfig(cfCfg)
		if err != nil {
			return fmt.Errorf("cloudflare provider: %w", err)
		}
		return client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
			dns01.DisableCompletePropagationRequirement(),
		)

	default:
		return fmt.Errorf("unsupported DNS provider %q (supported: cloudflare)", cert.Provider)
	}
}

// validateCertKeyPair verifies the returned PEM pair is coherent.
func validateCertKeyPair(certPEM, keyPEM []byte) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("empty certificate or key returned by CA")
	}
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	return err
}

// ─── ACME user ────────────────────────────────────────────────────────────────

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ─── Helpers ──────────────────────────────────────────────────────────────────

func parseCertExpiry(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.NotAfter.UTC().Format(time.RFC3339)
}

// normalizeBase64 将 Base64url（无 padding，含 - _）转换为标准 Base64（含 + /，有 padding）。
// ZeroSSL 下发的 HMAC Key 是 Base64url 格式，lego 内部用标准 Base64 解码，需做此转换。
func normalizeBase64(s string) string {
	// 先解码 Base64url（无 padding）
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// 如果解码失败，尝试标准 Base64url（有 padding）
		s2 := s
		switch len(s2) % 4 {
		case 2:
			s2 += "=="
		case 3:
			s2 += "="
		}
		raw, err = base64.URLEncoding.DecodeString(s2)
		if err != nil {
			// 已经是标准 Base64 或其他格式，直接补 padding 返回
			switch len(s) % 4 {
			case 2:
				s += "=="
			case 3:
				s += "="
			}
			return strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/")
		}
	}
	// 用标准 Base64 重新编码
	return base64.StdEncoding.EncodeToString(raw)
}

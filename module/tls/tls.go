package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/yourusername/vane/config"
)

type Manager struct {
	cfg *config.Config
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) StartAutoRenew() {
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		m.renewAll()
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
		days := c.DaysUntilExpiry()
		if days > 30 {
			continue
		}
		log.Printf("[tls] cert %s expires in %d days, renewing...", c.Domain, days)
		if err := m.IssueCert(c.ID); err != nil {
			log.Printf("[tls] renew %s error: %v", c.Domain, err)
		}
	}
}

// IssueCert triggers ACME DNS-01 cert issuance for a given cert config ID
func (m *Manager) IssueCert(certID string) error {
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

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	user := &acmeUser{email: cert.Email, key: privKey}
	cfg := lego.NewConfig(user)
	cfg.Certificate.KeyType = certcrypto.RSA2048
	// Use Let's Encrypt production
	// cfg.CADirURL = lego.LEDirectoryProduction

	client, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}

	// Setup DNS provider
	switch cert.Provider {
	case "cloudflare":
		cfCfg := cloudflare.NewDefaultConfig()
		cfCfg.AuthToken = cert.ProviderConf.APIToken
		provider, err := cloudflare.NewDNSProviderConfig(cfCfg)
		if err != nil {
			return err
		}
		if err := client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"})); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported ACME provider: %s", cert.Provider)
	}

	// Register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.registration = reg

	// Request cert
	request := certificate.ObtainRequest{
		Domains: []string{cert.Domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	// Parse expiry
	expiresAt := parseCertExpiry(certificates.Certificate)

	// Save to config
	m.cfg.Lock()
	for i := range m.cfg.TLSCerts {
		if m.cfg.TLSCerts[i].ID == certID {
			m.cfg.TLSCerts[i].CertPEM = string(certificates.Certificate)
			m.cfg.TLSCerts[i].KeyPEM = string(certificates.PrivateKey)
			m.cfg.TLSCerts[i].IssuedAt = config.Now()
			m.cfg.TLSCerts[i].ExpiresAt = expiresAt
			m.cfg.TLSCerts[i].Status = "active"
			break
		}
	}
	m.cfg.Unlock()
	return m.cfg.Save()
}

// ─── ACME user implementation ─────────────────────────────────────────────────

type acmeUser struct {
	email        string
	registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() interface{}               { return u.key }

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

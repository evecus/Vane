// Package config manages application configuration backed by an encrypted SQLite store.
// Sensitive fields (API tokens, TLS private keys, password hashes) never touch plain-text disk.
package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yourusername/vane/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	bucketAdmin    = "admin"
	bucketPF       = "portforward"
	bucketDDNS     = "ddns"
	bucketWS       = "webservice"
	bucketTLS      = "tls"
	keyAdminRecord = "record"
)

type Config struct {
	mu           sync.RWMutex
	db           *store.Store
	Admin        AdminConfig       `json:"admin"`
	PortForwards []PortForwardRule `json:"port_forwards"`
	DDNS         []DDNSRule        `json:"ddns"`
	WebServices  []WebService      `json:"web_services"`
	TLSCerts     []TLSCert         `json:"tls_certs"`
}

// ── AdminConfig ───────────────────────────────────────────────────────────────

type AdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt
	Port         int    `json:"port"`
	SafeEntry    string `json:"safe_entry"`
}

func (a *AdminConfig) CheckPassword(plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(plain)) == nil
}

func (a *AdminConfig) SetPassword(plain string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.PasswordHash = string(h)
	return nil
}

// ── PortForwardRule ───────────────────────────────────────────────────────────

type PortForwardRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"` // tcp | udp | both
	ListenPort int    `json:"listen_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

// ── DDNSRule ──────────────────────────────────────────────────────────────────

type DDNSRule struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Provider     string       `json:"provider"`
	Domain       string       `json:"domain"`
	SubDomain    string       `json:"sub_domain"`
	IPVersion    string       `json:"ip_version"`
	Interval     int          `json:"interval"`
	Enabled      bool         `json:"enabled"`
	ProviderConf ProviderConf `json:"provider_conf"`
	LastIP       string       `json:"last_ip"`
	LastUpdated  string       `json:"last_updated"`
	IPHistory    []IPRecord   `json:"ip_history"`
	CreatedAt    string       `json:"created_at"`
}

type ProviderConf struct {
	APIToken        string `json:"api_token,omitempty"`
	ZoneID          string `json:"zone_id,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	SecretID        string `json:"secret_id,omitempty"`
	SecretKey       string `json:"secret_key,omitempty"`
}

type IPRecord struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}

// ── WebService ────────────────────────────────────────────────────────────────
// HTTPS is mandatory. HTTP connections on ListenPort are redirected to HTTPS.
// An internal redirect listener runs on (ListenPort + 10000) to catch plain HTTP
// and issue 301 → https://<host>:<ListenPort><path>.

type WebService struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	ListenPort int        `json:"listen_port"`
	TLSCertID  string     `json:"tls_cert_id"` // required – no cert, no start
	Enabled    bool       `json:"enabled"`
	Routes     []WebRoute `json:"routes"`
	CreatedAt  string     `json:"created_at"`
}

type WebRoute struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	BackendURL string `json:"backend_url"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

type WebAccessLog struct {
	ID         string `json:"id"`
	ServiceID  string `json:"service_id"`
	RouteID    string `json:"route_id"`
	Domain     string `json:"domain"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Referer    string `json:"referer"`
	Time       string `json:"time"`
}

// ── TLSCert ───────────────────────────────────────────────────────────────────

type TLSCert struct {
	ID           string       `json:"id"`
	Domain       string       `json:"domain"`
	Source       string       `json:"source"`        // acme | manual
	Provider     string       `json:"provider"`      // cloudflare | alidns | dnspod
	ProviderConf ProviderConf `json:"provider_conf"` // AES-256-GCM encrypted at rest
	CertPEM      string       `json:"cert_pem"`      // AES-256-GCM encrypted at rest
	KeyPEM       string       `json:"key_pem"`       // AES-256-GCM encrypted at rest
	IssuedAt     string       `json:"issued_at"`
	ExpiresAt    string       `json:"expires_at"`
	AutoRenew    bool         `json:"auto_renew"`
	Email        string       `json:"email"`
	Status       string       `json:"status"` // pending | active | expired | error
	CreatedAt    string       `json:"created_at"`
}

func (c *TLSCert) DaysUntilExpiry() int {
	if c.ExpiresAt == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return -1
	}
	return int(time.Until(t).Hours() / 24)
}

// ── Load ──────────────────────────────────────────────────────────────────────

func Load(dbPath string) (*Config, error) {
	db, err := store.Open(dbPath, store.MachineSecret())
	if err != nil {
		return nil, fmt.Errorf("config load: %w", err)
	}

	cfg := &Config{db: db}
	if err := cfg.reload(); err != nil {
		return nil, err
	}

	// First-run defaults
	if cfg.Admin.Username == "" {
		cfg.Admin = AdminConfig{Username: "admin", Port: 4455}
		if err := cfg.Admin.SetPassword("admin"); err != nil {
			return nil, err
		}
		cfg.PortForwards = []PortForwardRule{}
		cfg.DDNS = []DDNSRule{}
		cfg.WebServices = []WebService{}
		cfg.TLSCerts = []TLSCert{}
		if err := cfg.persist(); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func (c *Config) reload() error {
	readList := func(bucket string, dst func(string) error) error {
		keys, err := c.db.Keys(bucket)
		if err != nil {
			return err
		}
		for _, k := range keys {
			v, ok, err := c.db.Get(bucket, k)
			if err != nil || !ok {
				continue
			}
			_ = dst(v)
		}
		return nil
	}

	if v, ok, err := c.db.Get(bucketAdmin, keyAdminRecord); err == nil && ok {
		_ = json.Unmarshal([]byte(v), &c.Admin)
	}

	c.PortForwards = []PortForwardRule{}
	_ = readList(bucketPF, func(v string) error {
		var r PortForwardRule
		if err := json.Unmarshal([]byte(v), &r); err == nil {
			c.PortForwards = append(c.PortForwards, r)
		}
		return nil
	})

	c.DDNS = []DDNSRule{}
	_ = readList(bucketDDNS, func(v string) error {
		var r DDNSRule
		if err := json.Unmarshal([]byte(v), &r); err == nil {
			c.DDNS = append(c.DDNS, r)
		}
		return nil
	})

	c.WebServices = []WebService{}
	_ = readList(bucketWS, func(v string) error {
		var s WebService
		if err := json.Unmarshal([]byte(v), &s); err == nil {
			c.WebServices = append(c.WebServices, s)
		}
		return nil
	})

	c.TLSCerts = []TLSCert{}
	_ = readList(bucketTLS, func(v string) error {
		var t TLSCert
		if err := json.Unmarshal([]byte(v), &t); err == nil {
			c.TLSCerts = append(c.TLSCerts, t)
		}
		return nil
	})

	return nil
}

func (c *Config) persist() error {
	if b, err := json.Marshal(c.Admin); err == nil {
		if err := c.db.Set(bucketAdmin, keyAdminRecord, string(b)); err != nil {
			return err
		}
	}
	_ = c.db.DeleteBucket(bucketPF)
	for _, r := range c.PortForwards {
		if b, err := json.Marshal(r); err == nil {
			_ = c.db.Set(bucketPF, r.ID, string(b))
		}
	}
	_ = c.db.DeleteBucket(bucketDDNS)
	for _, r := range c.DDNS {
		if b, err := json.Marshal(r); err == nil {
			_ = c.db.Set(bucketDDNS, r.ID, string(b))
		}
	}
	_ = c.db.DeleteBucket(bucketWS)
	for _, s := range c.WebServices {
		if b, err := json.Marshal(s); err == nil {
			_ = c.db.Set(bucketWS, s.ID, string(b))
		}
	}
	_ = c.db.DeleteBucket(bucketTLS)
	for _, t := range c.TLSCerts {
		if b, err := json.Marshal(t); err == nil {
			_ = c.db.Set(bucketTLS, t.ID, string(b))
		}
	}
	return nil
}

// Save flushes all in-memory state to the encrypted store.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persist()
}

// Targeted save helpers (avoid full rewrite for hot paths)

func (c *Config) SaveAdmin() error {
	b, err := json.Marshal(c.Admin)
	if err != nil {
		return err
	}
	return c.db.Set(bucketAdmin, keyAdminRecord, string(b))
}

func (c *Config) SaveSingleDDNS(r DDNSRule) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return c.db.Set(bucketDDNS, r.ID, string(b))
}

func (c *Config) Export() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	type shape struct {
		Admin        AdminConfig       `json:"admin"`
		PortForwards []PortForwardRule `json:"port_forwards"`
		DDNS         []DDNSRule        `json:"ddns"`
		WebServices  []WebService      `json:"web_services"`
		TLSCerts     []TLSCert         `json:"tls_certs"`
	}
	return json.MarshalIndent(shape{c.Admin, c.PortForwards, c.DDNS, c.WebServices, c.TLSCerts}, "", "  ")
}

func (c *Config) Import(data []byte) error {
	var tmp struct {
		Admin        AdminConfig       `json:"admin"`
		PortForwards []PortForwardRule `json:"port_forwards"`
		DDNS         []DDNSRule        `json:"ddns"`
		WebServices  []WebService      `json:"web_services"`
		TLSCerts     []TLSCert         `json:"tls_certs"`
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	if tmp.Admin.Username == "" {
		return fmt.Errorf("invalid backup: empty username")
	}
	if tmp.Admin.Port < 1 || tmp.Admin.Port > 65535 {
		return fmt.Errorf("invalid backup: bad port %d", tmp.Admin.Port)
	}
	c.mu.Lock()
	c.Admin = tmp.Admin
	c.PortForwards = tmp.PortForwards
	c.DDNS = tmp.DDNS
	c.WebServices = tmp.WebServices
	c.TLSCerts = tmp.TLSCerts
	err := c.persist()
	c.mu.Unlock()
	return err
}

func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }

func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

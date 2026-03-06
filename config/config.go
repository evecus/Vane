package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ─── Top-level config ────────────────────────────────────────────────────────

type Config struct {
	mu           sync.RWMutex       `json:"-"`
	filePath     string             `json:"-"`
	Admin        AdminConfig        `json:"admin"`
	PortForwards []PortForwardRule  `json:"port_forwards"`
	DDNS         []DDNSRule         `json:"ddns"`
	WebServices  []WebService       `json:"web_services"`
	TLSCerts     []TLSCert          `json:"tls_certs"`
}

// ─── Admin ───────────────────────────────────────────────────────────────────

type AdminConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Port         int    `json:"port"`
	// SafeEntry: if set, the dashboard is only reachable at /<SafeEntry>
	// e.g. "lucky88" → must visit http://ip:4455/lucky88
	SafeEntry string `json:"safe_entry"`
}

func (a *AdminConfig) CheckPassword(plain string) bool {
	return a.PasswordHash == hashPassword(plain)
}

func hashPassword(plain string) string {
	h := sha256.Sum256([]byte(plain + "vane-salt-2024"))
	return fmt.Sprintf("%x", h)
}

func (a *AdminConfig) SetPassword(plain string) {
	a.PasswordHash = hashPassword(plain)
}

// ─── Port Forward ────────────────────────────────────────────────────────────

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

// ─── DDNS ────────────────────────────────────────────────────────────────────

type DDNSRule struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Provider     string       `json:"provider"` // cloudflare | alidns | dnspod | tencentcloud
	Domain       string       `json:"domain"`
	SubDomain    string       `json:"sub_domain"`
	IPVersion    string       `json:"ip_version"` // ipv4 | ipv6
	Interval     int          `json:"interval"`   // seconds
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

// ─── Web Service ─────────────────────────────────────────────────────────────
//
// A WebService listens on one port and routes by domain to one or more
// sub-rules (WebRoute). When a browser hits  http://a.com:<port>  the server
// 301-redirects to  https://a.com:<port>  and proxies to the backend.

type WebService struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ListenPort  int        `json:"listen_port"`
	TLSCertID   string     `json:"tls_cert_id"`   // cert used for TLS on this port
	EnableHTTPS bool       `json:"enable_https"`  // serve HTTPS; redirect HTTP→HTTPS
	Enabled     bool       `json:"enabled"`
	Routes      []WebRoute `json:"routes"`
	CreatedAt   string     `json:"created_at"`
}

// WebRoute is one domain→backend sub-rule inside a WebService.
type WebRoute struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`      // e.g. "a.com"
	BackendURL string `json:"backend_url"` // e.g. "http://127.0.0.1:8080"
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

// WebAccessLog is one recorded request through the reverse proxy.
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

// ─── TLS Cert ────────────────────────────────────────────────────────────────

type TLSCert struct {
	ID           string       `json:"id"`
	Domain       string       `json:"domain"`
	Source       string       `json:"source"`   // acme | manual
	Provider     string       `json:"provider"` // cloudflare | alidns | dnspod
	ProviderConf ProviderConf `json:"provider_conf"`
	CertPEM      string       `json:"cert_pem"`
	KeyPEM       string       `json:"key_pem"`
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

// ─── Load / Save ─────────────────────────────────────────────────────────────

func Load(path string) (*Config, error) {
	cfg := &Config{filePath: path}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg.initDefaults(), nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.filePath = path
	return cfg, nil
}

// Save writes config to disk. Caller must NOT hold the write lock.
func (c *Config) Save() error {
	c.mu.RLock()
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(c.filePath, data, 0600)
}

// Export returns the JSON bytes of the current config (for backup download).
func (c *Config) Export() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.MarshalIndent(c, "", "  ")
}

// Import replaces config from JSON bytes (restore from backup).
func (c *Config) Import(data []byte) error {
	var tmp Config
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	c.mu.Lock()
	c.Admin = tmp.Admin
	c.PortForwards = tmp.PortForwards
	c.DDNS = tmp.DDNS
	c.WebServices = tmp.WebServices
	c.TLSCerts = tmp.TLSCerts
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) initDefaults() *Config {
	c.Admin = AdminConfig{
		Username:  "admin",
		Port:      4455,
		SafeEntry: "",
	}
	c.Admin.SetPassword("admin")
	c.PortForwards = []PortForwardRule{}
	c.DDNS = []DDNSRule{}
	c.WebServices = []WebService{}
	c.TLSCerts = []TLSCert{}
	_ = c.Save()
	return c
}

// ─── Thread-safe helpers ─────────────────────────────────────────────────────

func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }

func NewID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

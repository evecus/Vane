package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// ─── Encryption ───────────────────────────────────────────────────────────────

const encryptionKeyEnv = "VANE_SECRET"

// deriveKey derives a 32-byte AES key from a passphrase using PBKDF2-SHA256.
// Using PBKDF2 (100 000 iterations) instead of a bare SHA-256 makes brute-force
// attacks against the encrypted database ~100 000× more expensive.
//
// The salt is fixed ("vane-kdf-v1") because the key file itself is the secret;
// a per-file random salt would add no meaningful security here while
// complicating key recovery.
func deriveKey(passphrase string) []byte {
	const (
		kdfSalt   = "vane-kdf-v1"
		kdfIter   = 100_000
		kdfKeyLen = 32
	)
	return pbkdf2.Key([]byte(passphrase), []byte(kdfSalt), kdfIter, kdfKeyLen, sha256.New)
}

func encryptJSON(key []byte, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plain, nil)
	return hex.EncodeToString(ct), nil
}

func decryptJSON(key []byte, hexCT string, v any) error {
	ct, err := hex.DecodeString(hexCT)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(ct) < gcm.NonceSize() {
		return fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

func encryptStr(key []byte, s string) (string, error) {
	return encryptJSON(key, s)
}

func decryptStr(key []byte, hexCT string) (string, error) {
	var s string
	if err := decryptJSON(key, hexCT, &s); err != nil {
		return "", err
	}
	return s, nil
}

// ─── DataDir ──────────────────────────────────────────────────────────────────

type DataDir struct {
	Root string
	Key  []byte
	db   *sql.DB
}

func NewDataDir(customPath string) (*DataDir, error) {
	var root string

	if customPath != "" {
		// 如果用户指定了路径，建议转为绝对路径以避免相对路径偏移
		absPath, err := filepath.Abs(customPath)
		if err != nil {
			return nil, fmt.Errorf("invalid config path: %w", err)
		}
		root = absPath
	} else {
		// 原有的默认逻辑：程序所在目录下的 data 文件夹
		exe, err := os.Executable()
		if err != nil {
			exe = "."
		}
		root = filepath.Join(filepath.Dir(exe), "data")
	}

	// 创建目录
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dd := &DataDir{Root: root}
	if err := dd.loadOrCreateKey(); err != nil {
		return nil, err
	}
	if err := dd.openDB(); err != nil {
		return nil, err
	}
	return dd, nil
}

func (dd *DataDir) loadOrCreateKey() error {
	if secret := os.Getenv(encryptionKeyEnv); secret != "" {
		dd.Key = deriveKey(secret)
		return nil
	}
	keyFile := filepath.Join(dd.Root, "secret.key")
	data, err := os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, raw); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		encoded := hex.EncodeToString(raw)
		if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
			return fmt.Errorf("write secret.key: %w", err)
		}
		dd.Key = raw
		return nil
	}
	if err != nil {
		return fmt.Errorf("read secret.key: %w", err)
	}
	raw, err := hex.DecodeString(string(data))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid secret.key content")
	}
	dd.Key = raw
	return nil
}

func (dd *DataDir) openDB() error {
	dbPath := filepath.Join(dd.Root, "vane.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	dd.db = db
	return dd.migrate()
}

func (dd *DataDir) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS admin (
			id INTEGER PRIMARY KEY CHECK(id=1),
			username TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 4455,
			safe_entry TEXT NOT NULL DEFAULT '',
			welcome_shown INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS port_forwards (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT 'tcp',
			listen_port INTEGER NOT NULL,
			target_ip_enc TEXT NOT NULL DEFAULT '',
			target_port INTEGER NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ddns (
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
		)`,
		`CREATE TABLE IF NOT EXISTS web_services (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			listen_port INTEGER NOT NULL,
			enable_https INTEGER NOT NULL DEFAULT 1,
			enabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS web_routes (
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
		)`,
		`CREATE TABLE IF NOT EXISTS tls_certs (
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
		)`,
		`CREATE TABLE IF NOT EXISTS backups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			data_enc TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ip_filter_rules (
			id TEXT PRIMARY KEY,
			enabled INTEGER NOT NULL DEFAULT 0,
			mode TEXT NOT NULL DEFAULT 'whitelist',
			scopes_enc TEXT NOT NULL DEFAULT '',
			manual_ips_enc TEXT NOT NULL DEFAULT '',
			attachments_enc TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := dd.db.Exec(s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Migrate existing databases that may not have the welcome_shown column
	_, _ = dd.db.Exec(`ALTER TABLE admin ADD COLUMN welcome_shown INTEGER NOT NULL DEFAULT 0`)
	// Migrate web_routes to add cert matching columns
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN matched_cert_id TEXT NOT NULL DEFAULT ''`)
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN cert_status TEXT NOT NULL DEFAULT ''`)
	// Migrate web_routes to add auth columns
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN auth_enabled INTEGER NOT NULL DEFAULT 0`)
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN auth_user TEXT NOT NULL DEFAULT ''`)
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN auth_pass_hash TEXT NOT NULL DEFAULT ''`)
	// Migrate web_routes to add name column
	_, _ = dd.db.Exec(`ALTER TABLE web_routes ADD COLUMN name TEXT NOT NULL DEFAULT ''`)
	// Migrate ddns to add last sync status columns
	_, _ = dd.db.Exec(`ALTER TABLE ddns ADD COLUMN last_sync_ok INTEGER`)
	_, _ = dd.db.Exec(`ALTER TABLE ddns ADD COLUMN last_sync_err TEXT NOT NULL DEFAULT ''`)
	_, _ = dd.db.Exec(`ALTER TABLE ddns ADD COLUMN last_sync_at TEXT NOT NULL DEFAULT ''`)
	// Migrate web_services to drop tls_cert_id (SQLite can't DROP columns, just ignore it on load)
	return nil
}

func (dd *DataDir) DB() *sql.DB { return dd.db }

// ─── Types ────────────────────────────────────────────────────────────────────

type Config struct {
	mu      sync.RWMutex
	dataDir *DataDir

	Admin        AdminConfig       `json:"admin"`
	PortForwards []PortForwardRule `json:"port_forwards"`
	DDNS         []DDNSRule        `json:"ddns"`
	WebServices  []WebService      `json:"web_services"`
	TLSCerts     []TLSCert         `json:"tls_certs"`
	IPFilter     []IPFilterRule    `json:"ip_filter"`
}

// ─── IPFilter Types ───────────────────────────────────────────────────────────

// IPFilterAttachment represents a single uploaded IP list file.
type IPFilterAttachment struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

// IPFilterRule is one IP filtering policy applied to one or more scopes.
// Scopes values: "admin" | "portforward" | "webservice"
// Mode values:   "whitelist" | "blacklist"
type IPFilterRule struct {
	ID          string               `json:"id"`
	Enabled     bool                 `json:"enabled"`
	Mode        string               `json:"mode"`
	Scopes      []string             `json:"scopes"`
	ManualIPs   []string             `json:"manual_ips"`
	Attachments []IPFilterAttachment `json:"attachments"`
	CreatedAt   string               `json:"created_at"`
}

type AdminConfig struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`
	Port          int    `json:"port"`
	SafeEntry     string `json:"safe_entry"`
	WelcomeShown  bool   `json:"welcome_shown"`
}

func (a *AdminConfig) CheckPassword(plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(plain)) == nil
}

func (a *AdminConfig) SetPassword(plain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	a.PasswordHash = string(hash)
	return nil
}

type PortForwardRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	ListenPort int    `json:"listen_port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

type DDNSRule struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Provider     string       `json:"provider"`
	Domains      []string     `json:"domains"`
	Domain       string       `json:"domain,omitempty"`
	SubDomain    string       `json:"sub_domain,omitempty"`
	IPVersion    string       `json:"ip_version"`
	IPDetectMode string       `json:"ip_detect_mode"`
	IPInterface  string       `json:"ip_interface"`
	IPIndex      int          `json:"ip_index"`
	Interval     int          `json:"interval"`
	Enabled      bool         `json:"enabled"`
	ProviderConf ProviderConf `json:"provider_conf"`
	LastIP       string       `json:"last_ip"`
	LastUpdated  string       `json:"last_updated"`
	IPHistory    []IPRecord   `json:"ip_history"`
	CreatedAt    string       `json:"created_at"`
	// DNS 同步状态（运行时，不持久化）
	LastSyncOK  *bool  `json:"last_sync_ok,omitempty"`
	LastSyncErr string `json:"last_sync_err,omitempty"`
	LastSyncAt  string `json:"last_sync_at,omitempty"`
}

type ProviderConf struct {
	APIToken        string `json:"api_token,omitempty"`
	ZoneID          string `json:"zone_id,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
	SecretID        string `json:"secret_id,omitempty"`
	SecretKey       string `json:"secret_key,omitempty"`
	ZeroSSLAPIKey   string `json:"zerossl_api_key,omitempty"`
	ZeroSSLKeyID    string `json:"zerossl_key_id,omitempty"`
}

type IPRecord struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
}

type WebService struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ListenPort  int        `json:"listen_port"`
	EnableHTTPS bool       `json:"enable_https"`
	Enabled     bool       `json:"enabled"`
	Routes      []WebRoute `json:"routes"`
	CreatedAt   string     `json:"created_at"`
}

type WebRoute struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Domain        string `json:"domain"`
	BackendURL    string `json:"backend_url"`
	Enabled       bool   `json:"enabled"`
	MatchedCertID string `json:"matched_cert_id"`
	CertStatus    string `json:"cert_status"` // "ok" | "no_cert" | "cert_inactive"
	AuthEnabled   bool   `json:"auth_enabled"`
	AuthUser      string `json:"auth_user"`
	AuthPassHash  string `json:"auth_pass_hash,omitempty"` // bcrypt hash, never sent to frontend
	CreatedAt     string `json:"created_at"`
}

type WebAccessLog struct {
	ID         string `json:"id"`
	ServiceID  string `json:"service_id"`
	RouteID    string `json:"route_id"`
	RouteName  string `json:"route_name"`
	Domain     string `json:"domain"`
	StatusCode int    `json:"status_code"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	AuthResult string `json:"auth_result,omitempty"` // "ok" | "fail" | ""
	Time       string `json:"time"`
}

type TLSCert struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Domains      []string     `json:"domains"`
	Domain       string       `json:"domain,omitempty"`
	Source       string       `json:"source"`
	CAProvider   string       `json:"ca_provider"`
	Provider     string       `json:"provider"`
	ProviderConf ProviderConf `json:"provider_conf"`
	CertPEM      string       `json:"cert_pem"`
	KeyPEM       string       `json:"key_pem"`
	IssuedAt     string       `json:"issued_at"`
	ExpiresAt    string       `json:"expires_at"`
	AutoRenew    bool         `json:"auto_renew"`
	Email        string       `json:"email"`
	Status       string       `json:"status"`
	ErrorMsg     string       `json:"error_msg,omitempty"`
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

// ─── Load ─────────────────────────────────────────────────────────────────────

func Load(dd *DataDir) (*Config, error) {
	cfg := &Config{dataDir: dd}
	if err := cfg.loadFromDB(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) loadFromDB() error {
	key := c.dataDir.Key
	db := c.dataDir.db

	// Admin
	var username, passwordHash, safeEntry string
	var port int
	var welcomeShownInt int
	err := db.QueryRow(`SELECT username, password_hash, port, safe_entry, welcome_shown FROM admin WHERE id=1`).
		Scan(&username, &passwordHash, &port, &safeEntry, &welcomeShownInt)
	if err == sql.ErrNoRows {
		return c.initDefaults()
	}
	if err != nil {
		return fmt.Errorf("load admin: %w", err)
	}
	c.Admin = AdminConfig{Username: username, PasswordHash: passwordHash, Port: port, SafeEntry: safeEntry, WelcomeShown: welcomeShownInt == 1}

	// PortForwards
	rows, err := db.Query(`SELECT id, name, protocol, listen_port, target_ip_enc, target_port, enabled, created_at FROM port_forwards ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load port_forwards: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r PortForwardRule
		var enabledInt int
		var targetIPEnc string
		if err := rows.Scan(&r.ID, &r.Name, &r.Protocol, &r.ListenPort, &targetIPEnc, &r.TargetPort, &enabledInt, &r.CreatedAt); err != nil {
			return err
		}
		r.Enabled = enabledInt == 1
		if targetIPEnc != "" {
			r.TargetIP, _ = decryptStr(key, targetIPEnc)
		}
		c.PortForwards = append(c.PortForwards, r)
	}
	if c.PortForwards == nil {
		c.PortForwards = []PortForwardRule{}
	}

	// DDNS
	drows, err := db.Query(`SELECT id, name, provider, domains_enc, domain, sub_domain, ip_version, ip_detect_mode, ip_interface, ip_index, interval, enabled, provider_conf_enc, last_ip, last_updated, ip_history_enc, last_sync_ok, last_sync_err, last_sync_at, created_at FROM ddns ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load ddns: %w", err)
	}
	defer drows.Close()
	for drows.Next() {
		var r DDNSRule
		var enabledInt int
		var domainsEnc, providerConfEnc, ipHistoryEnc string
		var lastSyncOK sql.NullInt64
		if err := drows.Scan(&r.ID, &r.Name, &r.Provider, &domainsEnc, &r.Domain, &r.SubDomain,
			&r.IPVersion, &r.IPDetectMode, &r.IPInterface, &r.IPIndex, &r.Interval,
			&enabledInt, &providerConfEnc, &r.LastIP, &r.LastUpdated, &ipHistoryEnc,
			&lastSyncOK, &r.LastSyncErr, &r.LastSyncAt, &r.CreatedAt); err != nil {
			return err
		}
		if lastSyncOK.Valid {
			v := lastSyncOK.Int64 == 1
			r.LastSyncOK = &v
		}
		r.Enabled = enabledInt == 1
		if domainsEnc != "" {
			_ = decryptJSON(key, domainsEnc, &r.Domains)
		}
		if providerConfEnc != "" {
			_ = decryptJSON(key, providerConfEnc, &r.ProviderConf)
		}
		if ipHistoryEnc != "" {
			_ = decryptJSON(key, ipHistoryEnc, &r.IPHistory)
		}
		if r.Domains == nil {
			r.Domains = []string{}
		}
		if r.IPHistory == nil {
			r.IPHistory = []IPRecord{}
		}
		c.DDNS = append(c.DDNS, r)
	}
	if c.DDNS == nil {
		c.DDNS = []DDNSRule{}
	}

	// WebServices + Routes
	wsrows, err := db.Query(`SELECT id, name, listen_port, enable_https, enabled, created_at FROM web_services ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load web_services: %w", err)
	}
	defer wsrows.Close()
	for wsrows.Next() {
		var svc WebService
		var httpsInt, enabledInt int
		if err := wsrows.Scan(&svc.ID, &svc.Name, &svc.ListenPort, &httpsInt, &enabledInt, &svc.CreatedAt); err != nil {
			return err
		}
		svc.EnableHTTPS = httpsInt == 1
		svc.Enabled = enabledInt == 1
		rrows, err := db.Query(`SELECT id, name, domain, backend_url_enc, enabled, matched_cert_id, cert_status, auth_enabled, auth_user, auth_pass_hash, created_at FROM web_routes WHERE service_id=? ORDER BY created_at`, svc.ID)
		if err != nil {
			return err
		}
		for rrows.Next() {
			var route WebRoute
			var renabledInt, authEnabledInt int
			var backendEnc string
			if err := rrows.Scan(&route.ID, &route.Name, &route.Domain, &backendEnc, &renabledInt, &route.MatchedCertID, &route.CertStatus, &authEnabledInt, &route.AuthUser, &route.AuthPassHash, &route.CreatedAt); err != nil {
				rrows.Close()
				return err
			}
			route.Enabled = renabledInt == 1
			route.AuthEnabled = authEnabledInt == 1
			if backendEnc != "" {
				route.BackendURL, _ = decryptStr(key, backendEnc)
			}
			svc.Routes = append(svc.Routes, route)
		}
		rrows.Close()
		if svc.Routes == nil {
			svc.Routes = []WebRoute{}
		}
		c.WebServices = append(c.WebServices, svc)
	}
	if c.WebServices == nil {
		c.WebServices = []WebService{}
	}

	// TLSCerts
	trows, err := db.Query(`SELECT id, name, domains_enc, domain, source, ca_provider, provider, provider_conf_enc, cert_pem_enc, key_pem_enc, issued_at, expires_at, auto_renew, email, status, error_msg, created_at FROM tls_certs ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load tls_certs: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var cert TLSCert
		var autoRenewInt int
		var domainsEnc, providerConfEnc, certPEMEnc, keyPEMEnc string
		if err := trows.Scan(&cert.ID, &cert.Name, &domainsEnc, &cert.Domain, &cert.Source,
			&cert.CAProvider, &cert.Provider, &providerConfEnc, &certPEMEnc, &keyPEMEnc,
			&cert.IssuedAt, &cert.ExpiresAt, &autoRenewInt, &cert.Email, &cert.Status, &cert.ErrorMsg, &cert.CreatedAt); err != nil {
			return err
		}
		cert.AutoRenew = autoRenewInt == 1
		if domainsEnc != "" {
			_ = decryptJSON(key, domainsEnc, &cert.Domains)
		}
		if providerConfEnc != "" {
			_ = decryptJSON(key, providerConfEnc, &cert.ProviderConf)
		}
		if certPEMEnc != "" {
			cert.CertPEM, _ = decryptStr(key, certPEMEnc)
		}
		if keyPEMEnc != "" {
			cert.KeyPEM, _ = decryptStr(key, keyPEMEnc)
		}
		if cert.Domains == nil {
			cert.Domains = []string{}
		}
		c.TLSCerts = append(c.TLSCerts, cert)
	}
	if c.TLSCerts == nil {
		c.TLSCerts = []TLSCert{}
	}

	// IPFilter rules
	irows, err := db.Query(`SELECT id, enabled, mode, scopes_enc, manual_ips_enc, attachments_enc, created_at FROM ip_filter_rules ORDER BY created_at`)
	if err != nil {
		return fmt.Errorf("load ip_filter_rules: %w", err)
	}
	defer irows.Close()
	for irows.Next() {
		var rule IPFilterRule
		var enabledInt int
		var scopesEnc, manualIPsEnc, attachmentsEnc string
		if err := irows.Scan(&rule.ID, &enabledInt, &rule.Mode, &scopesEnc, &manualIPsEnc, &attachmentsEnc, &rule.CreatedAt); err != nil {
			return err
		}
		rule.Enabled = enabledInt == 1
		if scopesEnc != "" {
			_ = decryptJSON(key, scopesEnc, &rule.Scopes)
		}
		if manualIPsEnc != "" {
			_ = decryptJSON(key, manualIPsEnc, &rule.ManualIPs)
		}
		if attachmentsEnc != "" {
			_ = decryptJSON(key, attachmentsEnc, &rule.Attachments)
		}
		if rule.Scopes == nil {
			rule.Scopes = []string{}
		}
		if rule.ManualIPs == nil {
			rule.ManualIPs = []string{}
		}
		if rule.Attachments == nil {
			rule.Attachments = []IPFilterAttachment{}
		}
		c.IPFilter = append(c.IPFilter, rule)
	}
	if c.IPFilter == nil {
		c.IPFilter = []IPFilterRule{}
	}
	return nil
}

// ─── Atomic save helpers ──────────────────────────────────────────────────────

func (c *Config) SaveAdmin() error {
	welcomeShownInt := 0
	if c.Admin.WelcomeShown {
		welcomeShownInt = 1
	}
	_, err := c.dataDir.db.Exec(
		`INSERT INTO admin(id,username,password_hash,port,safe_entry,welcome_shown) VALUES(1,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET username=excluded.username, password_hash=excluded.password_hash, port=excluded.port, safe_entry=excluded.safe_entry, welcome_shown=excluded.welcome_shown`,
		c.Admin.Username, c.Admin.PasswordHash, c.Admin.Port, c.Admin.SafeEntry, welcomeShownInt,
	)
	return err
}

func (c *Config) SavePortForward(r PortForwardRule) error {
	key := c.dataDir.Key
	targetIPEnc, err := encryptStr(key, r.TargetIP)
	if err != nil {
		return err
	}
	enabledInt := boolToInt(r.Enabled)
	_, err = c.dataDir.db.Exec(
		`INSERT INTO port_forwards(id,name,protocol,listen_port,target_ip_enc,target_port,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, protocol=excluded.protocol, listen_port=excluded.listen_port, target_ip_enc=excluded.target_ip_enc, target_port=excluded.target_port, enabled=excluded.enabled`,
		r.ID, r.Name, r.Protocol, r.ListenPort, targetIPEnc, r.TargetPort, enabledInt, r.CreatedAt,
	)
	return err
}

func (c *Config) DeletePortForward(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM port_forwards WHERE id=?`, id)
	return err
}

func (c *Config) SaveDDNS(r DDNSRule) error {
	key := c.dataDir.Key
	domainsEnc, err := encryptJSON(key, r.Domains)
	if err != nil {
		return err
	}
	providerConfEnc, err := encryptJSON(key, r.ProviderConf)
	if err != nil {
		return err
	}
	ipHistoryEnc, err := encryptJSON(key, r.IPHistory)
	if err != nil {
		return err
	}
	var lastSyncOKVal interface{}
	if r.LastSyncOK != nil {
		if *r.LastSyncOK {
			lastSyncOKVal = 1
		} else {
			lastSyncOKVal = 0
		}
	}
	_, err = c.dataDir.db.Exec(
		`INSERT INTO ddns(id,name,provider,domains_enc,domain,sub_domain,ip_version,ip_detect_mode,ip_interface,ip_index,interval,enabled,provider_conf_enc,last_ip,last_updated,ip_history_enc,last_sync_ok,last_sync_err,last_sync_at,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, provider=excluded.provider, domains_enc=excluded.domains_enc, domain=excluded.domain, sub_domain=excluded.sub_domain, ip_version=excluded.ip_version, ip_detect_mode=excluded.ip_detect_mode, ip_interface=excluded.ip_interface, ip_index=excluded.ip_index, interval=excluded.interval, enabled=excluded.enabled, provider_conf_enc=excluded.provider_conf_enc, last_ip=excluded.last_ip, last_updated=excluded.last_updated, ip_history_enc=excluded.ip_history_enc, last_sync_ok=excluded.last_sync_ok, last_sync_err=excluded.last_sync_err, last_sync_at=excluded.last_sync_at`,
		r.ID, r.Name, r.Provider, domainsEnc, r.Domain, r.SubDomain,
		r.IPVersion, r.IPDetectMode, r.IPInterface, r.IPIndex, r.Interval,
		boolToInt(r.Enabled), providerConfEnc, r.LastIP, r.LastUpdated, ipHistoryEnc,
		lastSyncOKVal, r.LastSyncErr, r.LastSyncAt, r.CreatedAt,
	)
	return err
}

func (c *Config) DeleteDDNS(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM ddns WHERE id=?`, id)
	return err
}

func (c *Config) SaveWebService(svc WebService) error {
	_, err := c.dataDir.db.Exec(
		`INSERT INTO web_services(id,name,listen_port,enable_https,enabled,created_at) VALUES(?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, listen_port=excluded.listen_port, enable_https=excluded.enable_https, enabled=excluded.enabled`,
		svc.ID, svc.Name, svc.ListenPort, boolToInt(svc.EnableHTTPS), boolToInt(svc.Enabled), svc.CreatedAt,
	)
	return err
}

func (c *Config) DeleteWebService(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM web_services WHERE id=?`, id)
	return err
}

func (c *Config) SaveWebRoute(svcID string, route WebRoute) error {
	key := c.dataDir.Key
	backendEnc, err := encryptStr(key, route.BackendURL)
	if err != nil {
		return err
	}
	_, err = c.dataDir.db.Exec(
		`INSERT INTO web_routes(id,service_id,name,domain,backend_url_enc,enabled,matched_cert_id,cert_status,auth_enabled,auth_user,auth_pass_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, domain=excluded.domain, backend_url_enc=excluded.backend_url_enc, enabled=excluded.enabled, matched_cert_id=excluded.matched_cert_id, cert_status=excluded.cert_status, auth_enabled=excluded.auth_enabled, auth_user=excluded.auth_user, auth_pass_hash=excluded.auth_pass_hash`,
		route.ID, svcID, route.Name, route.Domain, backendEnc, boolToInt(route.Enabled), route.MatchedCertID, route.CertStatus, boolToInt(route.AuthEnabled), route.AuthUser, route.AuthPassHash, route.CreatedAt,
	)
	return err
}

func (c *Config) DeleteWebRoute(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM web_routes WHERE id=?`, id)
	return err
}

func (c *Config) SaveTLSCert(cert TLSCert) error {
	key := c.dataDir.Key
	domainsEnc, err := encryptJSON(key, cert.Domains)
	if err != nil {
		return err
	}
	providerConfEnc, err := encryptJSON(key, cert.ProviderConf)
	if err != nil {
		return err
	}
	certPEMEnc := ""
	if cert.CertPEM != "" {
		certPEMEnc, err = encryptStr(key, cert.CertPEM)
		if err != nil {
			return err
		}
	}
	keyPEMEnc := ""
	if cert.KeyPEM != "" {
		keyPEMEnc, err = encryptStr(key, cert.KeyPEM)
		if err != nil {
			return err
		}
	}
	_, err = c.dataDir.db.Exec(
		`INSERT INTO tls_certs(id,name,domains_enc,domain,source,ca_provider,provider,provider_conf_enc,cert_pem_enc,key_pem_enc,issued_at,expires_at,auto_renew,email,status,error_msg,created_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, domains_enc=excluded.domains_enc, domain=excluded.domain, source=excluded.source, ca_provider=excluded.ca_provider, provider=excluded.provider, provider_conf_enc=excluded.provider_conf_enc, cert_pem_enc=excluded.cert_pem_enc, key_pem_enc=excluded.key_pem_enc, issued_at=excluded.issued_at, expires_at=excluded.expires_at, auto_renew=excluded.auto_renew, email=excluded.email, status=excluded.status, error_msg=excluded.error_msg`,
		cert.ID, cert.Name, domainsEnc, cert.Domain, cert.Source, cert.CAProvider, cert.Provider,
		providerConfEnc, certPEMEnc, keyPEMEnc, cert.IssuedAt, cert.ExpiresAt,
		boolToInt(cert.AutoRenew), cert.Email, cert.Status, cert.ErrorMsg, cert.CreatedAt,
	)
	return err
}

func (c *Config) DeleteTLSCert(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM tls_certs WHERE id=?`, id)
	return err
}

func (c *Config) SaveIPFilterRule(rule IPFilterRule) error {
	key := c.dataDir.Key
	scopesEnc, err := encryptJSON(key, rule.Scopes)
	if err != nil {
		return err
	}
	manualIPsEnc, err := encryptJSON(key, rule.ManualIPs)
	if err != nil {
		return err
	}
	attachmentsEnc, err := encryptJSON(key, rule.Attachments)
	if err != nil {
		return err
	}
	_, err = c.dataDir.db.Exec(
		`INSERT INTO ip_filter_rules(id,enabled,mode,scopes_enc,manual_ips_enc,attachments_enc,created_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, mode=excluded.mode, scopes_enc=excluded.scopes_enc, manual_ips_enc=excluded.manual_ips_enc, attachments_enc=excluded.attachments_enc`,
		rule.ID, boolToInt(rule.Enabled), rule.Mode, scopesEnc, manualIPsEnc, attachmentsEnc, rule.CreatedAt,
	)
	return err
}

func (c *Config) DeleteIPFilterRule(id string) error {
	_, err := c.dataDir.db.Exec(`DELETE FROM ip_filter_rules WHERE id=?`, id)
	return err
}

// Save persists all in-memory state to the DB (used for bulk operations like restore).
func (c *Config) Save() error {
	c.mu.RLock()
	admin := c.Admin
	pfs := append([]PortForwardRule{}, c.PortForwards...)
	ddnsList := append([]DDNSRule{}, c.DDNS...)
	wsList := append([]WebService{}, c.WebServices...)
	tlsList := append([]TLSCert{}, c.TLSCerts...)
	ipfList := append([]IPFilterRule{}, c.IPFilter...)
	c.mu.RUnlock()

	c.Admin = admin
	if err := c.SaveAdmin(); err != nil {
		return err
	}
	for _, r := range pfs {
		if err := c.SavePortForward(r); err != nil {
			return err
		}
	}
	for _, r := range ddnsList {
		if err := c.SaveDDNS(r); err != nil {
			return err
		}
	}
	for _, svc := range wsList {
		if err := c.SaveWebService(svc); err != nil {
			return err
		}
		for _, route := range svc.Routes {
			if err := c.SaveWebRoute(svc.ID, route); err != nil {
				return err
			}
		}
	}
	for _, cert := range tlsList {
		if err := c.SaveTLSCert(cert); err != nil {
			return err
		}
	}
	for _, rule := range ipfList {
		if err := c.SaveIPFilterRule(rule); err != nil {
			return err
		}
	}
	return nil
}

// ─── Backup / Restore ─────────────────────────────────────────────────────────

// portableBackupKey is a fixed key derived from a well-known passphrase so that
// backup files can be restored on any machine (not tied to the local secret.key).
// The security model is: the backup file itself must be kept secret; the encryption
// prevents casual inspection and tampering but is not machine-locked.
var portableBackupKey = deriveKey("vane-portable-backup-v1")

// FullBackup contains every piece of configuration including admin credentials.
type FullBackup struct {
	Version      string            `json:"version"`
	Admin        AdminConfig       `json:"admin"`
	PortForwards []PortForwardRule `json:"port_forwards"`
	DDNS         []DDNSRule        `json:"ddns"`
	WebServices  []WebService      `json:"web_services"`
	TLSCerts     []TLSCert         `json:"tls_certs"`
	IPFilter     []IPFilterRule    `json:"ip_filter"`
}

// Export serialises the complete configuration (including admin account, port,
// safe-entry path, username and password hash) and encrypts it with a portable
// fixed key so the backup file can be restored on any machine.
func (c *Config) Export() ([]byte, error) {
	c.mu.RLock()
	snap := FullBackup{
		Version:      "2",
		Admin:        c.Admin,
		PortForwards: c.PortForwards,
		DDNS:         c.DDNS,
		WebServices:  c.WebServices,
		TLSCerts:     c.TLSCerts,
		IPFilter:     c.IPFilter,
	}
	c.mu.RUnlock()
	enc, err := encryptJSON(portableBackupKey, snap)
	if err != nil {
		return nil, err
	}
	return []byte(enc), nil
}

func (c *Config) SaveBackup() (string, error) {
	data, err := c.Export()
	if err != nil {
		return "", err
	}
	id := NewID()
	name := fmt.Sprintf("backup-%s.enc", time.Now().UTC().Format("20060102-150405"))
	_, err = c.dataDir.db.Exec(
		`INSERT INTO backups(id,name,data_enc,created_at) VALUES(?,?,?,?)`,
		id, name, string(data), Now(),
	)
	if err != nil {
		return "", err
	}
	return name, nil
}

// Import restores a full backup including admin credentials (username, password
// hash, port, safe-entry path).  The backup must have been created by Export and
// is decrypted with the portable fixed key.
func (c *Config) Import(data []byte) error {
	var snap FullBackup
	if err := decryptJSON(portableBackupKey, string(data), &snap); err != nil {
		return fmt.Errorf("invalid or unrecognised backup file: %w", err)
	}
	c.mu.Lock()
	c.Admin = snap.Admin
	c.PortForwards = snap.PortForwards
	c.DDNS = snap.DDNS
	c.WebServices = snap.WebServices
	c.TLSCerts = snap.TLSCerts
	if snap.IPFilter != nil {
		c.IPFilter = snap.IPFilter
	} else {
		c.IPFilter = []IPFilterRule{}
	}
	c.mu.Unlock()
	return c.Save()
}

// ─── Init defaults ────────────────────────────────────────────────────────────

// initDefaults sets up the initial admin account on first run.
// Default credentials are admin / admin — the dashboard will prompt
// the user to change the password on first login.
func (c *Config) initDefaults() error {
	c.Admin = AdminConfig{Username: "admin", Port: 4455}
	if err := c.Admin.SetPassword("admin"); err != nil {
		return err
	}
	c.PortForwards = []PortForwardRule{}
	c.DDNS = []DDNSRule{}
	c.WebServices = []WebService{}
	c.TLSCerts = []TLSCert{}
	c.IPFilter = []IPFilterRule{}
	return c.SaveAdmin()
}

// ─── Thread-safe helpers ──────────────────────────────────────────────────────

func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }

// ─── Utilities ────────────────────────────────────────────────────────────────

func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func IsPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

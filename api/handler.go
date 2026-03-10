package api

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/yourusername/vane/config"
	"github.com/yourusername/vane/module/ddns"
	"github.com/yourusername/vane/module/portforward"
	tlsmod "github.com/yourusername/vane/module/tls"
	"golang.org/x/crypto/bcrypt"
	"github.com/yourusername/vane/module/webservice"
)

var upgrader = websocket.Upgrader{
	// Verify Origin matches the admin host to prevent cross-origin WebSocket hijacking
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // same-origin non-browser requests
		}
		host := r.Host
		// Strip scheme from origin and compare host
		origin = strings.TrimPrefix(origin, "https://")
		origin = strings.TrimPrefix(origin, "http://")
		return strings.EqualFold(origin, host)
	},
}

type Handler struct {
	cfg            *config.Config
	pf             *portforward.Manager
	ddns           *ddns.Manager
	ws             *webservice.Manager
	tls            *tlsmod.Manager
	version        string
	disableSysinfo bool
}

func NewHandler(cfg *config.Config, pf *portforward.Manager, d *ddns.Manager,
	ws *webservice.Manager, t *tlsmod.Manager, version string, disableSysinfo bool) *Handler {
	return &Handler{cfg: cfg, pf: pf, ddns: d, ws: ws, tls: t, version: version, disableSysinfo: disableSysinfo}
}

// Register wires all routes.
func (h *Handler) Register(r *gin.Engine) {
	api := r.Group("/api")

	// Public
	api.POST("/login", h.rateLimitMiddleware(), h.login)
	api.POST("/logout", h.logout)

	auth := api.Group("/")
	auth.Use(h.authMiddleware())
	auth.GET("/session", h.session)

	// Dashboard + WS
	auth.GET("/dashboard", h.getDashboard)
	auth.GET("/sysinfo", h.getSysinfo)
	auth.GET("/ws/stats", h.wsStats)

	// Settings
	auth.GET("/settings", h.getSettings)
	auth.PUT("/settings", h.updateSettings)
	auth.POST("/settings/welcome-shown", h.markWelcomeShown)
	auth.GET("/settings/backup", h.backupConfig)
	auth.POST("/settings/restore", h.restoreConfig)

	// Port Forward
	auth.GET("/portforward", h.listPortForwards)
	auth.POST("/portforward", h.createPortForward)
	auth.PUT("/portforward/:id", h.updatePortForward)
	auth.DELETE("/portforward/:id", h.deletePortForward)
	auth.POST("/portforward/:id/toggle", h.togglePortForward)
	auth.GET("/portforward/:id/stats", h.getPortForwardStats)

	// DDNS
	auth.GET("/ddns", h.listDDNS)
	auth.GET("/ddns/interfaces", h.listInterfaces)
	auth.GET("/ddns/iface-ips", h.listIfaceIPs)
	auth.POST("/ddns", h.createDDNS)
	auth.PUT("/ddns/:id", h.updateDDNS)
	auth.DELETE("/ddns/:id", h.deleteDDNS)
	auth.POST("/ddns/:id/toggle", h.toggleDDNS)
	auth.POST("/ddns/:id/refresh", h.refreshDDNS)

	// Web Service
	auth.GET("/webservice", h.listWebServices)
	auth.POST("/webservice", h.createWebService)
	auth.PUT("/webservice/:id", h.updateWebService)
	auth.DELETE("/webservice/:id", h.deleteWebService)
	auth.POST("/webservice/:id/toggle", h.toggleWebService)
	auth.GET("/webservice/:id/routes", h.listRoutes)
	auth.POST("/webservice/:id/routes", h.createRoute)
	auth.PUT("/webservice/:id/routes/:rid", h.updateRoute)
	auth.DELETE("/webservice/:id/routes/:rid", h.deleteRoute)
	auth.POST("/webservice/:id/routes/:rid/toggle", h.toggleRoute)
	auth.GET("/webservice/:id/logs", h.getAccessLogs)
	auth.GET("/webservice/logs", h.getAllAccessLogs)

	// Port availability check
	auth.GET("/check-port", h.checkPort)

	// TLS
	auth.GET("/tls", h.listCerts)
	auth.POST("/tls", h.createCert)
	auth.PUT("/tls/:id", h.updateCert)
	auth.DELETE("/tls/:id", h.deleteCert)
	auth.POST("/tls/:id/issue", h.issueCert)
	auth.POST("/tls/upload", h.uploadCert)
	auth.GET("/tls/:id/download", h.downloadCert)
	auth.GET("/tls/:id/pem", h.getCertPEM)
}

// 鈹€鈹€鈹€ Safe Entry Middleware 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func SafeEntryMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg.RLock()
		entry := cfg.Admin.SafeEntry
		cfg.RUnlock()

		path := c.Request.URL.Path

		// Always allow API routes
		if strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}

		// Always allow static assets (JS/CSS/fonts/images embedded in index.html)
		// These use absolute paths like /assets/index-xxx.js regardless of safe_entry.
		if strings.HasPrefix(path, "/assets/") ||
			path == "/favicon.svg" || path == "/favicon.ico" ||
			path == "/favicon.png" || path == "/robots.txt" {
			c.Next()
			return
		}

		// No safe entry configured 鈫?allow everything
		if entry == "" {
			c.Next()
			return
		}

		prefix := "/" + strings.Trim(entry, "/")
		if strings.HasPrefix(path, prefix) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// 鈹€鈹€鈹€ Rate Limiter 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

type loginAttempt struct {
	count    int
	windowAt time.Time
}

var (
	loginMu       sync.Mutex
	loginAttempts = make(map[string]*loginAttempt)
)

const (
	maxLoginAttempts = 10
	loginWindow      = 10 * time.Minute
	sessionCookie    = "vane_session"
)

func init() {
	// Periodically purge old rate-limit entries to prevent unbounded memory growth
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			loginMu.Lock()
			now := time.Now()
			for ip, a := range loginAttempts {
				if now.Sub(a.windowAt) > loginWindow*2 {
					delete(loginAttempts, ip)
				}
			}
			loginMu.Unlock()
		}
	}()
}

func (h *Handler) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		loginMu.Lock()
		a, ok := loginAttempts[ip]
		if !ok || time.Since(a.windowAt) > loginWindow {
			loginAttempts[ip] = &loginAttempt{count: 0, windowAt: time.Now()}
			a = loginAttempts[ip]
		}
		a.count++
		count := a.count
		loginMu.Unlock()

		if count > maxLoginAttempts {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "鐧诲綍灏濊瘯娆℃暟杩囧锛岃10鍒嗛挓鍚庨噸璇?})
			c.Abort()
			return
		}
		c.Next()
	}
}

// 鈹€鈹€鈹€ Auth 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}
	h.cfg.RLock()
	ok := h.cfg.Admin.Username == req.Username && h.cfg.Admin.CheckPassword(req.Password)
	h.cfg.RUnlock()
	if !ok {
		c.JSON(401, gin.H{"error": "鐢ㄦ埛鍚嶆垨瀵嗙爜閿欒"})
		return
	}
	// Reset rate-limit counter on success
	loginMu.Lock()
	delete(loginAttempts, c.ClientIP())
	loginMu.Unlock()

	token := generateToken()
	sessions.set(token, time.Now().Add(24*time.Hour))
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookie, token, 24*3600, "/", "", requestIsHTTPS(c), true)
	c.JSON(200, gin.H{"token": token})
}

func (h *Handler) logout(c *gin.Context) {
	for _, token := range tokenCandidates(c) {
		sessions.delete(token)
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookie, "", -1, "/", "", requestIsHTTPS(c), true)
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		now := time.Now()
		var activeToken string
		for _, token := range tokenCandidates(c) {
			exp, ok := sessions.get(token)
			if !ok {
				continue
			}
			if now.After(exp) {
				sessions.delete(token)
				continue
			}
			activeToken = token
			break
		}
		if activeToken == "" {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		// Sliding expiry
		sessions.set(activeToken, time.Now().Add(24*time.Hour))
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(sessionCookie, activeToken, 24*3600, "/", "", requestIsHTTPS(c), true)
		c.Next()
	}
}

func (h *Handler) session(c *gin.Context) {
	c.JSON(200, gin.H{"authenticated": true})
}

func tokenCandidates(c *gin.Context) []string {
	candidates := make([]string, 0, 2)
	seen := map[string]struct{}{}
	if token, err := c.Cookie(sessionCookie); err == nil && token != "" {
		candidates = append(candidates, token)
		seen[token] = struct{}{}
	}
	if token := c.GetHeader("Authorization"); token != "" {
		if _, ok := seen[token]; !ok {
			candidates = append(candidates, token)
		}
	}
	return candidates
}

func requestIsHTTPS(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

// 鈹€鈹€鈹€ Dashboard 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) getDashboard(c *gin.Context) {
	h.cfg.RLock()
	certsSoon := 0
	for _, cert := range h.cfg.TLSCerts {
		d := cert.DaysUntilExpiry()
		if d >= 0 && d <= 30 {
			certsSoon++
		}
	}
	dash := gin.H{
		"port_forwards":       len(h.cfg.PortForwards),
		"ddns":                len(h.cfg.DDNS),
		"web_services":        len(h.cfg.WebServices),
		"tls_certs":           len(h.cfg.TLSCerts),
		"certs_expiring_soon": certsSoon,
	}
	h.cfg.RUnlock()
	c.JSON(200, dash)
}

func (h *Handler) wsStats(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.cfg.RLock()
		rules := make([]config.PortForwardRule, len(h.cfg.PortForwards))
		copy(rules, h.cfg.PortForwards)
		h.cfg.RUnlock()
		stats := make(map[string]interface{})
		for _, r := range rules {
			if s := h.pf.GetStats(r.ID); s != nil {
				stats[r.ID] = s.Snapshot()
			}
		}
		if err := conn.WriteJSON(gin.H{"type": "stats", "data": stats, "time": time.Now()}); err != nil {
			return
		}
	}
}

// 鈹€鈹€鈹€ Port check 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) checkPort(c *gin.Context) {
	portStr := c.Query("port")
	var port int
	if _, err := parsePort(portStr, &port); err != nil {
		c.JSON(400, gin.H{"error": "invalid port"})
		return
	}
	c.JSON(200, gin.H{"port": port, "available": config.IsPortAvailable(port)})
}

func parsePort(s string, out *int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	*out = n
	return n, nil
}

// 鈹€鈹€鈹€ Settings 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) getSettings(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, gin.H{
		"username":       h.cfg.Admin.Username,
		"port":           h.cfg.Admin.Port,
		"safe_entry":     h.cfg.Admin.SafeEntry,
		"version":        h.version,
		"welcome_shown":  h.cfg.Admin.WelcomeShown,
	})
}

func (h *Handler) markWelcomeShown(c *gin.Context) {
	h.cfg.Lock()
	h.cfg.Admin.WelcomeShown = true
	h.cfg.Unlock()
	if err := h.cfg.SaveAdmin(); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) updateSettings(c *gin.Context) {
	var req struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		Port            int    `json:"port"`
		SafeEntry       string `json:"safe_entry"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	oldPort := h.cfg.Admin.Port
	oldSafeEntry := h.cfg.Admin.SafeEntry
	// Require current password confirmation before changing credentials
	if req.NewPassword != "" {
		if !h.cfg.Admin.CheckPassword(req.CurrentPassword) {
			h.cfg.Unlock()
			c.JSON(403, gin.H{"error": "褰撳墠瀵嗙爜閿欒"})
			return
		}
		if err := h.cfg.Admin.SetPassword(req.NewPassword); err != nil {
			h.cfg.Unlock()
			c.JSON(500, gin.H{"error": "瀵嗙爜璁剧疆澶辫触"})
			return
		}
	}
	if req.Username != "" {
		h.cfg.Admin.Username = req.Username
	}
	if req.Port > 0 {
		h.cfg.Admin.Port = req.Port
	}
	h.cfg.Admin.SafeEntry = strings.Trim(req.SafeEntry, "/")
	admin := h.cfg.Admin
	h.cfg.Unlock()

	// Save only admin row
	h.cfg.Lock()
	h.cfg.Admin = admin
	h.cfg.Unlock()
	if err := h.cfg.SaveAdmin(); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨閰嶇疆澶辫触: " + err.Error()})
		return
	}

	// If port changed, respond first then restart the process so it binds the new port.
	portChanged := req.Port > 0 && req.Port != oldPort
	safeEntryChanged := strings.Trim(req.SafeEntry, "/") != strings.Trim(oldSafeEntry, "/")
	needsLogout := portChanged || safeEntryChanged

	if needsLogout {
		sessions.clearAll()
	}

	c.JSON(200, gin.H{"ok": true, "restart": portChanged, "logout": needsLogout})

	if portChanged {
		go func() {
			// Give the HTTP response time to flush to the client before we exit.
			time.Sleep(800 * time.Millisecond)
			restartSelf()
		}()
	}
}

// restartSelf re-executes the current binary with the same arguments and
// environment, effectively restarting the server on the newly configured port.
// If exec fails (e.g. binary path unavailable) we fall back to os.Exit so that
// a process supervisor (systemd, Docker restart policy, etc.) will relaunch us.
func restartSelf() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("restart: os.Executable error: %v 鈥?falling back to os.Exit", err)
		os.Exit(0)
	}
	// Resolve symlinks so syscall.Exec gets the real binary path.
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	log.Printf("restart: re-executing %s %v", exe, os.Args[1:])
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Printf("restart: syscall.Exec error: %v 鈥?falling back to os.Exit", err)
		os.Exit(0)
	}
}

func (h *Handler) backupConfig(c *gin.Context) {
	name, err := h.cfg.SaveBackup()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	data, err := h.cfg.Export()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// Use filepath.Base to sanitize the filename
	safeName := filepath.Base(name)
	c.Header("Content-Disposition", `attachment; filename="`+safeName+`"`)
	c.Data(200, "application/octet-stream", data)
}

func (h *Handler) restoreConfig(c *gin.Context) {
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, 10<<20)) // 10 MB max
	if err != nil {
		c.JSON(400, gin.H{"error": "read body failed"})
		return
	}
	if err := h.cfg.Import(data); err != nil {
		c.JSON(400, gin.H{"error": "invalid config: " + err.Error()})
		return
	}
	h.pf.StartAll()
	h.ddns.StartAll()
	h.ws.StartAll()
	c.JSON(200, gin.H{"ok": true, "message": "閰嶇疆宸叉仮澶嶏紝鏈嶅姟宸查噸鍚?})
}

// 鈹€鈹€鈹€ Port Forward 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listPortForwards(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.PortForwards)
}

func (h *Handler) createPortForward(c *gin.Context) {
	var rule config.PortForwardRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if rule.ListenPort < 1 || rule.ListenPort > 65535 {
		c.JSON(400, gin.H{"error": "鏃犳晥绔彛"})
		return
	}
	if rule.Enabled && !config.IsPortAvailable(rule.ListenPort) {
		c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": rule.ListenPort})
		return
	}
	rule.ID = config.NewID()
	rule.CreatedAt = config.Now()
	h.cfg.Lock()
	h.cfg.PortForwards = append(h.cfg.PortForwards, rule)
	h.cfg.Unlock()
	if err := h.cfg.SavePortForward(rule); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if rule.Enabled {
		_ = h.pf.Start(rule.ID)
	}
	c.JSON(201, rule)
}

func (h *Handler) updatePortForward(c *gin.Context) {
	id := c.Param("id")
	var req config.PortForwardRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.pf.Stop(id)
	if req.Enabled && !config.IsPortAvailable(req.ListenPort) {
		c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": req.ListenPort})
		return
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.PortForwards {
		if h.cfg.PortForwards[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.PortForwards[i].CreatedAt
			h.cfg.PortForwards[i] = req
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if err := h.cfg.SavePortForward(req); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if req.Enabled {
		_ = h.pf.Start(id)
	}
	c.JSON(200, req)
}

func (h *Handler) deletePortForward(c *gin.Context) {
	id := c.Param("id")
	h.pf.Stop(id)
	h.cfg.Lock()
	for i, r := range h.cfg.PortForwards {
		if r.ID == id {
			h.cfg.PortForwards = append(h.cfg.PortForwards[:i], h.cfg.PortForwards[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.DeletePortForward(id); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) togglePortForward(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	var port int
	found := false
	for i := range h.cfg.PortForwards {
		if h.cfg.PortForwards[i].ID == id {
			h.cfg.PortForwards[i].Enabled = !h.cfg.PortForwards[i].Enabled
			enabled = h.cfg.PortForwards[i].Enabled
			port = h.cfg.PortForwards[i].ListenPort
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if enabled {
		h.pf.Stop(id)
		if !config.IsPortAvailable(port) {
			// Roll back in memory
			h.cfg.Lock()
			for i := range h.cfg.PortForwards {
				if h.cfg.PortForwards[i].ID == id {
					h.cfg.PortForwards[i].Enabled = false
					break
				}
			}
			h.cfg.Unlock()
			// Persist the rollback
			h.cfg.RLock()
			var r config.PortForwardRule
			for _, pf := range h.cfg.PortForwards {
				if pf.ID == id {
					r = pf
					break
				}
			}
			h.cfg.RUnlock()
			_ = h.cfg.SavePortForward(r)
			c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": port})
			return
		}
		_ = h.pf.Start(id)
	} else {
		h.pf.Stop(id)
	}
	// Persist final state
	h.cfg.RLock()
	var r config.PortForwardRule
	for _, pf := range h.cfg.PortForwards {
		if pf.ID == id {
			r = pf
			break
		}
	}
	h.cfg.RUnlock()
	if err := h.cfg.SavePortForward(r); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (h *Handler) getPortForwardStats(c *gin.Context) {
	c.JSON(200, gin.H{"history": h.pf.GetHistory(c.Param("id"))})
}

// 鈹€鈹€鈹€ DDNS 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listDDNS(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.DDNS)
}

func (h *Handler) createDDNS(c *gin.Context) {
	var rule config.DDNSRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	rule.ID = config.NewID()
	rule.CreatedAt = config.Now()
	h.cfg.Lock()
	h.cfg.DDNS = append(h.cfg.DDNS, rule)
	h.cfg.Unlock()
	if err := h.cfg.SaveDDNS(rule); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if rule.Enabled {
		h.ddns.Start(rule.ID)
	}
	c.JSON(201, rule)
}

func (h *Handler) updateDDNS(c *gin.Context) {
	id := c.Param("id")
	var req config.DDNSRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.DDNS {
		if h.cfg.DDNS[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.DDNS[i].CreatedAt
			h.cfg.DDNS[i] = req
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if err := h.cfg.SaveDDNS(req); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	h.ddns.Stop(id)
	if req.Enabled {
		h.ddns.Start(id)
	}
	c.JSON(200, req)
}

func (h *Handler) deleteDDNS(c *gin.Context) {
	id := c.Param("id")
	h.ddns.Stop(id)
	h.cfg.Lock()
	for i, r := range h.cfg.DDNS {
		if r.ID == id {
			h.cfg.DDNS = append(h.cfg.DDNS[:i], h.cfg.DDNS[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.DeleteDDNS(id); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleDDNS(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	found := false
	for i := range h.cfg.DDNS {
		if h.cfg.DDNS[i].ID == id {
			h.cfg.DDNS[i].Enabled = !h.cfg.DDNS[i].Enabled
			enabled = h.cfg.DDNS[i].Enabled
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	h.cfg.RLock()
	var r config.DDNSRule
	for _, d := range h.cfg.DDNS {
		if d.ID == id {
			r = d
			break
		}
	}
	h.cfg.RUnlock()
	if err := h.cfg.SaveDDNS(r); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if enabled {
		h.ddns.Start(id)
	} else {
		h.ddns.Stop(id)
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (h *Handler) refreshDDNS(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	found := false
	for _, d := range h.cfg.DDNS {
		if d.ID == id {
			found = true
			break
		}
	}
	h.cfg.RUnlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	// Stop the background worker so TriggerNow doesn't race with it
	h.ddns.Stop(id)
	res, err := h.ddns.TriggerNow(id)
	// Restart the worker if the rule is still enabled
	h.cfg.RLock()
	var enabled bool
	for _, d := range h.cfg.DDNS {
		if d.ID == id {
			enabled = d.Enabled
			break
		}
	}
	h.cfg.RUnlock()
	if enabled {
		h.ddns.Start(id)
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, res)
}

// 鈹€鈹€鈹€ Web Service 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listWebServices(c *gin.Context) {
	h.cfg.RLock()
	svcs := make([]config.WebService, len(h.cfg.WebServices))
	copy(svcs, h.cfg.WebServices)
	h.cfg.RUnlock()
	// Never expose password hashes to frontend
	for i := range svcs {
		for j := range svcs[i].Routes {
			svcs[i].Routes[j].AuthPassHash = ""
		}
	}
	c.JSON(200, svcs)
}

func (h *Handler) createWebService(c *gin.Context) {
	var svc config.WebService
	if err := c.ShouldBindJSON(&svc); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if svc.ListenPort < 1 || svc.ListenPort > 65535 {
		c.JSON(400, gin.H{"error": "鏃犳晥绔彛"})
		return
	}
	svc.EnableHTTPS = true
	if svc.Enabled && !config.IsPortAvailable(svc.ListenPort) {
		c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": svc.ListenPort})
		return
	}
	svc.ID = config.NewID()
	svc.CreatedAt = config.Now()
	if svc.Routes == nil {
		svc.Routes = []config.WebRoute{}
	}
	h.cfg.Lock()
	h.cfg.WebServices = append(h.cfg.WebServices, svc)
	h.cfg.Unlock()
	if err := h.cfg.SaveWebService(svc); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if svc.Enabled {
		if err := h.ws.Start(svc.ID); err != nil {
			log.Printf("[webservice] start %s failed: %v", svc.ID, err)
		}
	}
	c.JSON(201, svc)
}

func (h *Handler) updateWebService(c *gin.Context) {
	id := c.Param("id")
	var req config.WebService
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	req.EnableHTTPS = true // always
	h.ws.Stop(id)
	if req.Enabled && !config.IsPortAvailable(req.ListenPort) {
		c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": req.ListenPort})
		return
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.WebServices[i].CreatedAt
			if req.Routes == nil {
				req.Routes = h.cfg.WebServices[i].Routes
			}
			h.cfg.WebServices[i] = req
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if err := h.cfg.SaveWebService(req); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	if req.Enabled {
		if err := h.ws.Start(id); err != nil {
			log.Printf("[webservice] start %s failed: %v", id, err)
		}
	}
	c.JSON(200, req)
}

func (h *Handler) deleteWebService(c *gin.Context) {
	id := c.Param("id")
	h.ws.Stop(id)
	h.cfg.Lock()
	for i, s := range h.cfg.WebServices {
		if s.ID == id {
			h.cfg.WebServices = append(h.cfg.WebServices[:i], h.cfg.WebServices[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.DeleteWebService(id); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleWebService(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	var enabled bool
	var port int
	found := false
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			h.cfg.WebServices[i].Enabled = !h.cfg.WebServices[i].Enabled
			enabled = h.cfg.WebServices[i].Enabled
			port = h.cfg.WebServices[i].ListenPort
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if enabled {
		h.ws.Stop(id)
		if !config.IsPortAvailable(port) {
			h.cfg.Lock()
			for i := range h.cfg.WebServices {
				if h.cfg.WebServices[i].ID == id {
					h.cfg.WebServices[i].Enabled = false
					break
				}
			}
			h.cfg.Unlock()
			h.cfg.RLock()
			var svc config.WebService
			for _, s := range h.cfg.WebServices {
				if s.ID == id {
					svc = s
					break
				}
			}
			h.cfg.RUnlock()
			_ = h.cfg.SaveWebService(svc)
			c.JSON(409, gin.H{"error": "绔彛宸茶鍗犵敤", "port": port})
			return
		}
		if err := h.ws.Start(id); err != nil {
			// Roll back enabled state
			h.cfg.Lock()
			for i := range h.cfg.WebServices {
				if h.cfg.WebServices[i].ID == id {
					h.cfg.WebServices[i].Enabled = false
					break
				}
			}
			h.cfg.Unlock()
			h.cfg.RLock()
			var svc config.WebService
			for _, s := range h.cfg.WebServices {
				if s.ID == id {
					svc = s
					break
				}
			}
			h.cfg.RUnlock()
			_ = h.cfg.SaveWebService(svc)
			errMsg := err.Error()
			if strings.Contains(errMsg, "no routes have a matched certificate") {
				errMsg = "璇峰厛娣诲姞瀛愯鍒欙紝璇佷功鍖归厤鎴愬姛鍚庢柟鍙惎鍔?
			}
			c.JSON(500, gin.H{"error": "鏈嶅姟鍚姩澶辫触: " + errMsg})
			return
		}
	} else {
		h.ws.Stop(id)
	}
	h.cfg.RLock()
	var svc config.WebService
	for _, s := range h.cfg.WebServices {
		if s.ID == id {
			svc = s
			break
		}
	}
	h.cfg.RUnlock()
	if err := h.cfg.SaveWebService(svc); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

// 鈹€鈹€鈹€ Web Routes 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listRoutes(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	for _, svc := range h.cfg.WebServices {
		if svc.ID == id {
			c.JSON(200, svc.Routes)
			return
		}
	}
	c.JSON(404, gin.H{"error": "service not found"})
}

// hashRoutePassword hashes a plain-text password for a WebRoute.
// If authEnabled is false or password is empty, it returns the existing hash unchanged.
func hashRoutePassword(plain, existingHash string, authEnabled bool) (string, error) {
	if !authEnabled || plain == "" {
		return existingHash, nil
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func (h *Handler) createRoute(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		config.WebRoute
		AuthPass string `json:"auth_pass"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	route := req.WebRoute
	if route.AuthEnabled {
		if route.AuthUser == "" || req.AuthPass == "" {
			c.JSON(400, gin.H{"error": "寮€鍚闂獙璇佹椂锛岃处鍙峰拰瀵嗙爜涓嶈兘涓虹┖"})
			return
		}
		hash, err := hashRoutePassword(req.AuthPass, "", true)
		if err != nil {
			c.JSON(500, gin.H{"error": "瀵嗙爜鍔犲瘑澶辫触"})
			return
		}
		route.AuthPassHash = hash
	} else {
		route.AuthUser = ""
		route.AuthPassHash = ""
	}
	route.ID = config.NewID()
	route.CreatedAt = config.Now()
	h.cfg.Lock()
	found := false
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == id {
			h.cfg.WebServices[i].Routes = append(h.cfg.WebServices[i].Routes, route)
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "service not found"})
		return
	}
	if err := h.cfg.SaveWebRoute(id, route); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	h.ws.MatchRouteCert(id, &route)
	h.ws.Stop(id)
	_ = h.ws.Start(id)
	route.AuthPassHash = "" // never expose hash
	c.JSON(201, route)
}

func (h *Handler) updateRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	var req struct {
		config.WebRoute
		AuthPass string `json:"auth_pass"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	route := req.WebRoute
	if route.AuthEnabled {
		if route.AuthUser == "" || (req.AuthPass == "" && route.AuthPassHash == "") {
			c.JSON(400, gin.H{"error": "寮€鍚闂獙璇佹椂锛岃处鍙峰拰瀵嗙爜涓嶈兘涓虹┖"})
			return
		}
	} else {
		route.AuthUser = ""
		route.AuthPassHash = ""
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			for j := range h.cfg.WebServices[i].Routes {
				if h.cfg.WebServices[i].Routes[j].ID == rid {
					route.ID = rid
					route.CreatedAt = h.cfg.WebServices[i].Routes[j].CreatedAt
					// Keep existing hash if no new password provided
					if route.AuthEnabled && req.AuthPass == "" {
						route.AuthPassHash = h.cfg.WebServices[i].Routes[j].AuthPassHash
					} else if route.AuthEnabled && req.AuthPass != "" {
						hash, err := bcrypt.GenerateFromPassword([]byte(req.AuthPass), bcrypt.DefaultCost)
						if err != nil {
							h.cfg.Unlock()
							c.JSON(500, gin.H{"error": "瀵嗙爜鍔犲瘑澶辫触"})
							return
						}
						route.AuthPassHash = string(hash)
					}
					h.cfg.WebServices[i].Routes[j] = route
					found = true
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "route not found"})
		return
	}
	if err := h.cfg.SaveWebRoute(svcID, route); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	h.ws.MatchRouteCert(svcID, &route)
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	route.AuthPassHash = "" // never expose hash
	c.JSON(200, route)
}

func (h *Handler) deleteRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	h.cfg.Lock()
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			routes := h.cfg.WebServices[i].Routes
			for j, r := range routes {
				if r.ID == rid {
					h.cfg.WebServices[i].Routes = append(routes[:j], routes[j+1:]...)
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.DeleteWebRoute(rid); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) toggleRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	h.cfg.Lock()
	var enabled bool
	var updatedRoute config.WebRoute
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			for j := range h.cfg.WebServices[i].Routes {
				if h.cfg.WebServices[i].Routes[j].ID == rid {
					h.cfg.WebServices[i].Routes[j].Enabled = !h.cfg.WebServices[i].Routes[j].Enabled
					enabled = h.cfg.WebServices[i].Routes[j].Enabled
					updatedRoute = h.cfg.WebServices[i].Routes[j]
					break
				}
			}
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.SaveWebRoute(svcID, updatedRoute); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	h.ws.MatchRouteCert(svcID, &updatedRoute)
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, gin.H{"enabled": enabled})
}

// 鈹€鈹€鈹€ Access Logs 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) getAccessLogs(c *gin.Context) {
	c.JSON(200, webservice.GetLogs().List(c.Param("id"), 200))
}

func (h *Handler) getAllAccessLogs(c *gin.Context) {
	c.JSON(200, webservice.GetLogs().List("", 500))
}

// 鈹€鈹€鈹€ TLS 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listCerts(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	type certView struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Domain    string `json:"domain"`
		Domains   []string `json:"domains"`
		Source    string `json:"source"`
		CAProvider string `json:"ca_provider"`
		Provider  string `json:"provider"`
		IssuedAt  string `json:"issued_at"`
		ExpiresAt string `json:"expires_at"`
		AutoRenew bool   `json:"auto_renew"`
		Status    string `json:"status"`
		ErrorMsg  string `json:"error_msg,omitempty"`
		DaysLeft  int    `json:"days_left"`
		CreatedAt string `json:"created_at"`
	}
	views := make([]certView, 0, len(h.cfg.TLSCerts))
	for _, cert := range h.cfg.TLSCerts {
		views = append(views, certView{
			ID: cert.ID, Name: cert.Name, Domain: cert.Domain, Domains: cert.Domains,
			Source: cert.Source, CAProvider: cert.CAProvider, Provider: cert.Provider,
			IssuedAt: cert.IssuedAt, ExpiresAt: cert.ExpiresAt, AutoRenew: cert.AutoRenew,
			Status: cert.Status, ErrorMsg: cert.ErrorMsg,
			DaysLeft: cert.DaysUntilExpiry(), CreatedAt: cert.CreatedAt,
		})
	}
	c.JSON(200, views)
}

func (h *Handler) createCert(c *gin.Context) {
	var cert config.TLSCert
	if err := c.ShouldBindJSON(&cert); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	cert.ID = config.NewID()
	cert.CreatedAt = config.Now()
	cert.Status = "pending"
	h.cfg.Lock()
	h.cfg.TLSCerts = append(h.cfg.TLSCerts, cert)
	h.cfg.Unlock()
	if err := h.cfg.SaveTLSCert(cert); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	go h.ws.RematchAllRoutes()
	c.JSON(201, cert)
}

func (h *Handler) updateCert(c *gin.Context) {
	id := c.Param("id")
	var req config.TLSCert
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			req.ID = id
			req.CreatedAt = h.cfg.TLSCerts[i].CreatedAt
			// Preserve existing cert/key if not replaced
			if req.CertPEM == "" {
				req.CertPEM = h.cfg.TLSCerts[i].CertPEM
				req.KeyPEM = h.cfg.TLSCerts[i].KeyPEM
				req.IssuedAt = h.cfg.TLSCerts[i].IssuedAt
				req.ExpiresAt = h.cfg.TLSCerts[i].ExpiresAt
				req.Status = h.cfg.TLSCerts[i].Status
			}
			h.cfg.TLSCerts[i] = req
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	if err := h.cfg.SaveTLSCert(req); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	go h.ws.RematchAllRoutes()
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) deleteCert(c *gin.Context) {
	id := c.Param("id")
	h.cfg.Lock()
	for i, cert := range h.cfg.TLSCerts {
		if cert.ID == id {
			h.cfg.TLSCerts = append(h.cfg.TLSCerts[:i], h.cfg.TLSCerts[i+1:]...)
			break
		}
	}
	h.cfg.Unlock()
	if err := h.cfg.DeleteTLSCert(id); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	go h.ws.RematchAllRoutes()
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) issueCert(c *gin.Context) {
	id := c.Param("id")
	// Mark as pending immediately
	h.cfg.Lock()
	found := false
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			h.cfg.TLSCerts[i].Status = "pending"
			h.cfg.TLSCerts[i].ErrorMsg = ""
			found = true
			break
		}
	}
	h.cfg.Unlock()
	if !found {
		c.JSON(404, gin.H{"error": "cert not found"})
		return
	}
	h.cfg.RLock()
	var pending config.TLSCert
	for _, cert := range h.cfg.TLSCerts {
		if cert.ID == id {
			pending = cert
			break
		}
	}
	h.cfg.RUnlock()
	_ = h.cfg.SaveTLSCert(pending)

	// Issue asynchronously
	go func() {
		err := h.tls.IssueCert(id)
		h.cfg.Lock()
		for i := range h.cfg.TLSCerts {
			if h.cfg.TLSCerts[i].ID == id {
				if err != nil {
					log.Printf("[tls] issueCert %s failed: %v", id, err)
					h.cfg.TLSCerts[i].Status = "error"
					h.cfg.TLSCerts[i].ErrorMsg = err.Error()
					certCopy := h.cfg.TLSCerts[i]
					h.cfg.Unlock()
					_ = h.cfg.SaveTLSCert(certCopy)
					go h.ws.RematchAllRoutes()
					return
				}
				// Success: tls.IssueCert already persisted the cert
				break
			}
		}
		h.cfg.Unlock()
		go h.ws.RematchAllRoutes()
	}()

	c.JSON(202, gin.H{"ok": true, "message": "璇佷功鐢宠宸插紑濮嬶紝璇风◢鍚庡埛鏂版煡鐪嬬姸鎬?})
}

func (h *Handler) uploadCert(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "璇蜂笂浼犺瘉涔?ZIP 鏂囦欢"})
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(file)
	if err != nil {
		c.JSON(400, gin.H{"error": "璇诲彇鏂囦欢澶辫触"})
		return
	}

	// Parse zip
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		c.JSON(400, gin.H{"error": "鏃犳硶瑙ｆ瀽 ZIP 鏂囦欢: " + err.Error()})
		return
	}

	var certPEM, keyPEM string
	for _, f := range zr.File {
		name := strings.ToLower(filepath.Base(f.Name))
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, _ := io.ReadAll(rc)
		rc.Close()
		switch name {
		case "cert.pem", "fullchain.pem", "certificate.pem":
			certPEM = string(content)
		case "key.pem", "privkey.pem", "private.pem":
			keyPEM = string(content)
		}
	}

	if certPEM == "" || keyPEM == "" {
		c.JSON(400, gin.H{"error": "ZIP 涓湭鎵惧埌璇佷功鏂囦欢锛堥渶鍖呭惈 cert.pem/fullchain.pem 鍜?key.pem/privkey.pem锛?})
		return
	}

	// Validate PEM pair
	if _, err := tlsParsePair(certPEM, keyPEM); err != nil {
		c.JSON(400, gin.H{"error": "鏃犳晥鐨勮瘉涔︽垨绉侀挜: " + err.Error()})
		return
	}

	// Extract domains from cert SAN
	domains := extractDomainsFromCertPEM(certPEM)
	domain := ""
	if len(domains) > 0 {
		domain = domains[0]
	}

	cert := config.TLSCert{
		ID:        config.NewID(),
		Name:      domain,
		Domain:    domain,
		Domains:   domains,
		Source:    "manual",
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		IssuedAt:  config.Now(),
		AutoRenew: false,
		Status:    "active",
		CreatedAt: config.Now(),
	}
	h.cfg.Lock()
	h.cfg.TLSCerts = append(h.cfg.TLSCerts, cert)
	h.cfg.Unlock()
	if err := h.cfg.SaveTLSCert(cert); err != nil {
		c.JSON(500, gin.H{"error": "淇濆瓨澶辫触"})
		return
	}
	go h.ws.RematchAllRoutes()
	c.JSON(201, cert)
}

// extractDomainsFromCertPEM parses a PEM certificate and returns all SANs (DNS names).
func extractDomainsFromCertPEM(certPEM string) []string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var domains []string
	for _, name := range x509Cert.DNSNames {
		if !seen[name] {
			seen[name] = true
			domains = append(domains, name)
		}
	}
	// Fallback to CN if no SANs
	if len(domains) == 0 && x509Cert.Subject.CommonName != "" {
		domains = append(domains, x509Cert.Subject.CommonName)
	}
	return domains
}

func (h *Handler) downloadCert(c *gin.Context) {
	id := c.Param("id")
	h.cfg.RLock()
	var found *config.TLSCert
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			cert := h.cfg.TLSCerts[i]
			found = &cert
			break
		}
	}
	h.cfg.RUnlock()
	if found == nil {
		c.JSON(404, gin.H{"error": "cert not found"})
		return
	}
	if found.CertPEM == "" || found.KeyPEM == "" {
		c.JSON(400, gin.H{"error": "璇佷功灏氭湭绛惧彂锛屾棤娉曚笅杞?})
		return
	}

	// Build zip in memory
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}

	_ = addFile("cert.pem", found.CertPEM)
	_ = addFile("key.pem", found.KeyPEM)

	// info.json with domains and metadata
	domains := found.Domains
	if len(domains) == 0 && found.Domain != "" {
		domains = []string{found.Domain}
	}
	info := map[string]interface{}{
		"domain":     found.Domain,
		"domains":    domains,
		"issued_at":  found.IssuedAt,
		"expires_at": found.ExpiresAt,
		"source":     found.Source,
		"name":       found.Name,
	}
	infoJSON, _ := json.MarshalIndent(info, "", "  ")
	_ = addFile("info.json", string(infoJSON))

	zw.Close()

	safeName := sanitizeFilename(found.Domain)
	if safeName == "" {
		safeName = "cert"
	}
	c.Header("Content-Disposition", `attachment; filename="`+safeName+`-certs.zip"`)
	c.Data(200, "application/zip", buf.Bytes())
}

func (h *Handler) getCertPEM(c *gin.Context) {
	id := c.Param("id")
	includeKey := strings.EqualFold(c.DefaultQuery("include_key", "0"), "1") ||
		strings.EqualFold(c.DefaultQuery("include_key", ""), "true")

	h.cfg.RLock()
	var found *config.TLSCert
	for i := range h.cfg.TLSCerts {
		if h.cfg.TLSCerts[i].ID == id {
			cert := h.cfg.TLSCerts[i]
			found = &cert
			break
		}
	}
	h.cfg.RUnlock()
	if found == nil {
		c.JSON(404, gin.H{"error": "cert not found"})
		return
	}

	resp := gin.H{
		"cert_pem": found.CertPEM,
		"domain":   found.Domain,
	}
	if includeKey {
		log.Printf("[security] private key export requested cert_id=%s ip=%s", id, c.ClientIP())
		resp["key_pem"] = found.KeyPEM
	} else {
		resp["key_pem"] = ""
	}
	c.JSON(200, resp)
}

// 鈹€鈹€鈹€ DDNS helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) listInterfaces(c *gin.Context) {
	c.JSON(200, ddns.GetInterfaces())
}

func (h *Handler) listIfaceIPs(c *gin.Context) {
	iface := c.Query("iface")
	version := c.DefaultQuery("version", "ipv4")
	if iface == "" {
		c.JSON(400, gin.H{"error": "iface required"})
		return
	}
	ips, err := ddns.ListInterfaceIPs(iface, version)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ips)
}

// 鈹€鈹€鈹€ Utility helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func tlsParsePair(certPEM, keyPEM string) (interface{}, error) {
	_, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	return nil, err
}

// sanitizeFilename strips any characters that could be used in header injection.
func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '"' || r == '\r' || r == '\n' || r == '\\' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// 鈹€鈹€鈹€ Sysinfo 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (h *Handler) getSysinfo(c *gin.Context) {
	if h.disableSysinfo {
		c.JSON(200, gin.H{"disabled": true})
		return
	}
	c.JSON(200, gin.H{
		"os":      readSysinfoOS(),
		"kernel":  readSysinfoKernel(),
		"arch":    readSysinfoArch(),
		"uptime":  readSysinfoUptime(),
		"memory":  readSysinfoMemory(),
		"disk":    readSysinfoDisk("/"),
		"network": readSysinfoNetworkTraffic(),
		"ifaces":  readSysinfoIfaces(),
	})
}

// readSysinfoOS reads /etc/os-release for PRETTY_NAME, falls back to uname.
func readSysinfoOS() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v := strings.TrimPrefix(line, "PRETTY_NAME=")
				v = strings.Trim(v, "\"")
				return v
			}
		}
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			return "Linux " + fields[2]
		}
	}
	return "Unknown"
}

// readSysinfoArch returns the CPU architecture from uname or runtime.
func readSysinfoArch() string {
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOARCH
}

// readSysinfoKernel returns the kernel version from /proc/version.
func readSysinfoKernel() string {
	if data, err := os.ReadFile("/proc/version"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			return fields[2]
		}
	}
	return "鈥?
}

// readSysinfoUptime parses /proc/uptime and returns seconds + human string.
func readSysinfoUptime() map[string]interface{} {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			var secs float64
			fmt.Sscanf(fields[0], "%f", &secs)
			total := int64(secs)
			days := total / 86400
			hours := (total % 86400) / 3600
			mins := (total % 3600) / 60
			human := ""
			if days > 0 {
				human += fmt.Sprintf("%d澶?, days)
			}
			if hours > 0 {
				human += fmt.Sprintf("%d灏忔椂", hours)
			}
			human += fmt.Sprintf("%d鍒嗛挓", mins)
			return map[string]interface{}{"seconds": total, "human": human}
		}
	}
	return map[string]interface{}{"seconds": 0, "human": "鈥?}
}

// readSysinfoMemory reads /proc/meminfo and returns used/total KB + percentage.
func readSysinfoMemory() map[string]interface{} {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	m := make(map[string]uint64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		var val uint64
		fmt.Sscanf(fields[1], "%d", &val)
		m[key] = val
	}
	total := m["MemTotal"]
	free := m["MemFree"]
	buffers := m["Buffers"]
	cached := m["Cached"]
	sReclaimable := m["SReclaimable"]
	used := total - free - buffers - cached - sReclaimable
	if total == 0 {
		return nil
	}
	pct := fmt.Sprintf("%.1f", float64(used)/float64(total)*100)
	return map[string]interface{}{
		"total_kb": total,
		"used_kb":  used,
		"free_kb":  free,
		"pct":      pct,
	}
}

// readSysinfoDisk reads disk usage for a given mount point via /proc/mounts + syscall.Statfs.
func readSysinfoDisk(mountPoint string) map[string]interface{} {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &stat); err != nil {
		return nil
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	totalKB := total / 1024
	usedKB := used / 1024
	if totalKB == 0 {
		return nil
	}
	pct := fmt.Sprintf("%.1f", float64(usedKB)/float64(totalKB)*100)
	return map[string]interface{}{
		"total_kb": totalKB,
		"used_kb":  usedKB,
		"pct":      pct,
	}
}

// isVirtualIface detects virtual/software-only interfaces via /sys/class/net attributes.
// This is OS-agnostic and does not rely on interface naming conventions.
//
// Logic:
//  1. type == 772 (ARPHRD_LOOPBACK) 鈫?skip
//  2. tun_flags file exists 鈫?TUN/TAP 鈫?skip
//  3. device/ symlink exists 鈫?bound to a real hardware driver 鈫?keep
//  4. bridge/ or bonding/ dir exists 鈫?software bridge/bond but carries real traffic 鈫?keep
//  5. ifindex != iflink 鈫?veth pair (peer lives in another netns) 鈫?skip
//  6. Everything else has no hardware device 鈫?skip (dummy, sit, ip6tnl, macvlan, etc.)
func isVirtualIface(name string) bool {
	base := "/sys/class/net/" + name

	// 1. Loopback type (ARPHRD_LOOPBACK = 772)
	if data, err := os.ReadFile(base + "/type"); err == nil {
		if strings.TrimSpace(string(data)) == "772" {
			return true
		}
	}

	// 2. TUN/TAP: tun_flags exists
	if _, err := os.Stat(base + "/tun_flags"); err == nil {
		return true
	}

	// 3. Hardware device symlink 鈫?physical NIC
	if _, err := os.Stat(base + "/device"); err == nil {
		return false
	}

	// 4. Software bridge or bonding master 鈫?keep (carries real traffic)
	if _, err := os.Stat(base + "/bridge"); err == nil {
		return false
	}
	if _, err := os.Stat(base + "/bonding"); err == nil {
		return false
	}

	// 5. veth pair: iflink points to peer in another netns, so ifindex != iflink
	ifidxData, err1 := os.ReadFile(base + "/ifindex")
	iflinkData, err2 := os.ReadFile(base + "/iflink")
	if err1 == nil && err2 == nil {
		if strings.TrimSpace(string(ifidxData)) != strings.TrimSpace(string(iflinkData)) {
			return true
		}
	}

	// 6. No hardware device, not a bridge/bond 鈫?software-only
	return true
}

// readSysinfoNetworkTraffic reads cumulative RX/TX bytes from /proc/net/dev,
// showing only physical/bridge interfaces.
func readSysinfoNetworkTraffic() []map[string]interface{} {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var result []map[string]interface{}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[2:] { // skip header lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		if isVirtualIface(iface) {
			continue
		}
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		var rx, tx uint64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)
		result = append(result, map[string]interface{}{
			"iface":    iface,
			"rx_bytes": rx,
			"tx_bytes": tx,
		})
	}
	return result
}

// readSysinfoIfaces returns IPs for physical interfaces only,
// filtering out link-local IPv6 (fe80::) and keeping public + private IPs.
func readSysinfoIfaces() []map[string]interface{} {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []map[string]interface{}
	for _, iface := range ifaces {
		if isVirtualIface(iface.Name) {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ips []string
		for _, addr := range addrs {
			s := addr.String()
			// Skip link-local IPv6 fe80::/10
			ip, _, _ := net.ParseCIDR(s)
			if ip == nil {
				ip = net.ParseIP(s)
			}
			if ip != nil && ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, s)
		}
		if len(ips) > 0 {
			result = append(result, map[string]interface{}{
				"name": iface.Name,
				"ips":  ips,
			})
		}
	}
	return result
}

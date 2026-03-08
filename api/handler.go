package api

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	cfg  *config.Config
	pf   *portforward.Manager
	ddns *ddns.Manager
	ws   *webservice.Manager
	tls  *tlsmod.Manager
}

func NewHandler(cfg *config.Config, pf *portforward.Manager, d *ddns.Manager,
	ws *webservice.Manager, t *tlsmod.Manager) *Handler {
	return &Handler{cfg: cfg, pf: pf, ddns: d, ws: ws, tls: t}
}

// Register wires all routes.
func (h *Handler) Register(r *gin.Engine) {
	api := r.Group("/api")

	// Public
	api.POST("/login", h.rateLimitMiddleware(), h.login)
	api.POST("/logout", h.logout)

	auth := api.Group("/")
	auth.Use(h.authMiddleware())

	// Dashboard + WS
	auth.GET("/dashboard", h.getDashboard)
	auth.GET("/sysinfo", h.getSysInfo)
	auth.GET("/ws/stats", h.wsStats)

	// Settings
	auth.GET("/settings", h.getSettings)
	auth.PUT("/settings", h.updateSettings)
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

// ─── Safe Entry Middleware ────────────────────────────────────────────────────

func SafeEntryMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg.RLock()
		entry := cfg.Admin.SafeEntry
		cfg.RUnlock()

		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}
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

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

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
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试次数过多，请10分钟后重试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

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
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}
	// Reset rate-limit counter on success
	loginMu.Lock()
	delete(loginAttempts, c.ClientIP())
	loginMu.Unlock()

	token := generateToken()
	sessions.set(token, time.Now().Add(24*time.Hour))
	c.JSON(200, gin.H{"token": token})
}

func (h *Handler) logout(c *gin.Context) {
	sessions.delete(c.GetHeader("Authorization"))
	c.JSON(200, gin.H{"ok": true})
}

func (h *Handler) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		exp, ok := sessions.get(token)
		if !ok || time.Now().After(exp) {
			sessions.delete(token)
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		// Sliding expiry
		sessions.set(token, time.Now().Add(24*time.Hour))
		c.Next()
	}
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

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

// ─── Port check ───────────────────────────────────────────────────────────────

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

// ─── Settings ─────────────────────────────────────────────────────────────────

func (h *Handler) getSettings(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, gin.H{
		"username":   h.cfg.Admin.Username,
		"port":       h.cfg.Admin.Port,
		"safe_entry": h.cfg.Admin.SafeEntry,
	})
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
	// Require current password confirmation before changing credentials
	if req.NewPassword != "" {
		if !h.cfg.Admin.CheckPassword(req.CurrentPassword) {
			h.cfg.Unlock()
			c.JSON(403, gin.H{"error": "当前密码错误"})
			return
		}
		if err := h.cfg.Admin.SetPassword(req.NewPassword); err != nil {
			h.cfg.Unlock()
			c.JSON(500, gin.H{"error": "密码设置失败"})
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
		c.JSON(500, gin.H{"error": "保存配置失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
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
	c.JSON(200, gin.H{"ok": true, "message": "配置已恢复，服务已重启"})
}

// ─── Port Forward ─────────────────────────────────────────────────────────────

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
		c.JSON(400, gin.H{"error": "无效端口"})
		return
	}
	if rule.Enabled && !config.IsPortAvailable(rule.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": rule.ListenPort})
		return
	}
	rule.ID = config.NewID()
	rule.CreatedAt = config.Now()
	h.cfg.Lock()
	h.cfg.PortForwards = append(h.cfg.PortForwards, rule)
	h.cfg.Unlock()
	if err := h.cfg.SavePortForward(rule); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(409, gin.H{"error": "端口已被占用", "port": req.ListenPort})
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
			c.JSON(409, gin.H{"error": "端口已被占用", "port": port})
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (h *Handler) getPortForwardStats(c *gin.Context) {
	c.JSON(200, gin.H{"history": h.pf.GetHistory(c.Param("id"))})
}

// ─── DDNS ─────────────────────────────────────────────────────────────────────

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
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
	// Check existence first
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
	h.ddns.Stop(id)
	h.ddns.Start(id)
	c.JSON(200, gin.H{"ok": true})
}

// ─── Web Service ──────────────────────────────────────────────────────────────

func (h *Handler) listWebServices(c *gin.Context) {
	h.cfg.RLock()
	defer h.cfg.RUnlock()
	c.JSON(200, h.cfg.WebServices)
}

func (h *Handler) createWebService(c *gin.Context) {
	var svc config.WebService
	if err := c.ShouldBindJSON(&svc); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if svc.ListenPort < 1 || svc.ListenPort > 65535 {
		c.JSON(400, gin.H{"error": "无效端口"})
		return
	}
	// All web services require HTTPS
	svc.EnableHTTPS = true
	if svc.TLSCertID == "" {
		c.JSON(400, gin.H{"error": "Web服务必须配置SSL证书才能启动"})
		return
	}
	if svc.Enabled && !config.IsPortAvailable(svc.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": svc.ListenPort})
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if svc.Enabled {
		if err := h.ws.Start(svc.ID); err != nil {
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
			return
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
	if req.TLSCertID == "" {
		c.JSON(400, gin.H{"error": "Web服务必须配置SSL证书"})
		return
	}
	h.ws.Stop(id)
	if req.Enabled && !config.IsPortAvailable(req.ListenPort) {
		c.JSON(409, gin.H{"error": "端口已被占用", "port": req.ListenPort})
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	if req.Enabled {
		if err := h.ws.Start(id); err != nil {
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
			return
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
			c.JSON(409, gin.H{"error": "端口已被占用", "port": port})
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
			c.JSON(500, gin.H{"error": "服务启动失败: " + err.Error()})
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

// ─── Web Routes ───────────────────────────────────────────────────────────────

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

func (h *Handler) createRoute(c *gin.Context) {
	id := c.Param("id")
	var route config.WebRoute
	if err := c.ShouldBindJSON(&route); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(id)
	_ = h.ws.Start(id)
	c.JSON(201, route)
}

func (h *Handler) updateRoute(c *gin.Context) {
	svcID, rid := c.Param("id"), c.Param("rid")
	var req config.WebRoute
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.cfg.Lock()
	found := false
	for i := range h.cfg.WebServices {
		if h.cfg.WebServices[i].ID == svcID {
			for j := range h.cfg.WebServices[i].Routes {
				if h.cfg.WebServices[i].Routes[j].ID == rid {
					req.ID = rid
					req.CreatedAt = h.cfg.WebServices[i].Routes[j].CreatedAt
					h.cfg.WebServices[i].Routes[j] = req
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
	if err := h.cfg.SaveWebRoute(svcID, req); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, req)
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
		c.JSON(500, gin.H{"error": "保存失败"})
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	h.ws.Stop(svcID)
	_ = h.ws.Start(svcID)
	c.JSON(200, gin.H{"enabled": enabled})
}

// ─── Access Logs ──────────────────────────────────────────────────────────────

func (h *Handler) getAccessLogs(c *gin.Context) {
	c.JSON(200, webservice.GetLogs().List(c.Param("id"), 200))
}

func (h *Handler) getAllAccessLogs(c *gin.Context) {
	c.JSON(200, webservice.GetLogs().List("", 500))
}

// ─── TLS ──────────────────────────────────────────────────────────────────────

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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
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
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
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
					return
				}
				// Success: tls.IssueCert already persisted the cert
				break
			}
		}
		h.cfg.Unlock()
	}()

	c.JSON(202, gin.H{"ok": true, "message": "证书申请已开始，请稍后刷新查看状态"})
}

func (h *Handler) uploadCert(c *gin.Context) {
	var req struct {
		Domain    string `json:"domain"`
		CertPEM   string `json:"cert_pem"`
		KeyPEM    string `json:"key_pem"`
		AutoRenew bool   `json:"auto_renew"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// Validate PEM pair before storing
	if _, err := tlsParsePair(req.CertPEM, req.KeyPEM); err != nil {
		c.JSON(400, gin.H{"error": "无效的证书或私钥: " + err.Error()})
		return
	}
	cert := config.TLSCert{
		ID:        config.NewID(),
		Domain:    req.Domain,
		Domains:   []string{req.Domain},
		Source:    "manual",
		CertPEM:   req.CertPEM,
		KeyPEM:    req.KeyPEM,
		IssuedAt:  config.Now(),
		AutoRenew: req.AutoRenew,
		Status:    "active",
		CreatedAt: config.Now(),
	}
	h.cfg.Lock()
	h.cfg.TLSCerts = append(h.cfg.TLSCerts, cert)
	h.cfg.Unlock()
	if err := h.cfg.SaveTLSCert(cert); err != nil {
		c.JSON(500, gin.H{"error": "保存失败"})
		return
	}
	c.JSON(201, cert)
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
		c.JSON(400, gin.H{"error": "证书尚未签发，无法下载"})
		return
	}
	// Sanitize domain for use in filename
	domain := sanitizeFilename(found.Domain)
	c.Header("Content-Disposition", `attachment; filename="`+domain+`-cert.pem"`)
	c.Data(200, "application/x-pem-file", []byte(found.CertPEM))
}

func (h *Handler) getCertPEM(c *gin.Context) {
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
	c.JSON(200, gin.H{
		"cert_pem": found.CertPEM,
		"key_pem":  found.KeyPEM,
		"domain":   found.Domain,
	})
}

// ─── DDNS helpers ─────────────────────────────────────────────────────────────

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

// ─── SysInfo ──────────────────────────────────────────────────────────────────

func (h *Handler) getSysInfo(c *gin.Context) {
	info := gin.H{
		"os":      readSysOSName(),
		"kernel":  readSysKernel(),
		"uptime":  readSysUptime(),
		"memory":  readSysMemory(),
		"disk":    readSysDisk(),
		"network": readSysNetworkTraffic(),
		"ifaces":  readSysIfaceIPs(),
	}
	c.JSON(200, info)
}

func readSysOSName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	return "Linux"
}

func readSysKernel() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(data))
}

func readSysUptime() map[string]interface{} {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return map[string]interface{}{"seconds": 0, "human": "N/A"}
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return map[string]interface{}{"seconds": 0, "human": "N/A"}
	}
	var secs float64
	fmt.Sscanf(fields[0], "%f", &secs)
	d := int(secs)
	days := d / 86400
	hours := (d % 86400) / 3600
	mins := (d % 3600) / 60
	var human string
	if days > 0 {
		human = fmt.Sprintf("%d天 %d时 %d分", days, hours, mins)
	} else if hours > 0 {
		human = fmt.Sprintf("%d时 %d分", hours, mins)
	} else {
		human = fmt.Sprintf("%d分钟", mins)
	}
	return map[string]interface{}{"seconds": int(secs), "human": human}
}

func readSysMemory() map[string]interface{} {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	vals := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			var v uint64
			fmt.Sscanf(parts[1], "%d", &v)
			key := strings.TrimSuffix(parts[0], ":")
			vals[key] = v
		}
	}
	total := vals["MemTotal"]
	avail := vals["MemAvailable"]
	used := total - avail
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return map[string]interface{}{
		"total_kb": total,
		"used_kb":  used,
		"free_kb":  avail,
		"pct":      fmt.Sprintf("%.1f", pct),
	}
}

func readSysDisk() map[string]interface{} {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return map[string]interface{}{"total_kb": uint64(0), "used_kb": uint64(0), "pct": "0.0"}
	}
	total := stat.Blocks * uint64(stat.Bsize) / 1024
	free := stat.Bfree * uint64(stat.Bsize) / 1024
	used := total - free
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return map[string]interface{}{
		"total_kb": total,
		"used_kb":  used,
		"free_kb":  free,
		"pct":      fmt.Sprintf("%.1f", pct),
	}
}

func readSysNetworkTraffic() []map[string]interface{} {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var result []map[string]interface{}
	lines := strings.Split(string(data), "\n")
	if len(lines) <= 2 {
		return result
	}
	for _, line := range lines[2:] {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 10 {
			continue
		}
		iface := strings.TrimSuffix(fields[0], ":")
		if iface == "lo" {
			continue
		}
		var rxBytes, txBytes uint64
		fmt.Sscanf(fields[1], "%d", &rxBytes)
		fmt.Sscanf(fields[9], "%d", &txBytes)
		result = append(result, map[string]interface{}{
			"iface":    iface,
			"rx_bytes": rxBytes,
			"tx_bytes": txBytes,
		})
	}
	return result
}

func readSysIfaceIPs() []map[string]interface{} {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []map[string]interface{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var ips []string
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
		if len(ips) > 0 {
			result = append(result, map[string]interface{}{
				"name": iface.Name,
				"ips":  ips,
				"mac":  iface.HardwareAddr.String(),
			})
		}
	}
	return result
}

// ─── Utility helpers ──────────────────────────────────────────────────────────


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

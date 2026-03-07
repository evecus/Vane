package main

import (
	"embed"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/yourusername/vane/api"
	"github.com/yourusername/vane/config"
	"github.com/yourusername/vane/module/ddns"
	"github.com/yourusername/vane/module/portforward"
	"github.com/yourusername/vane/module/tls"
	"github.com/yourusername/vane/module/webservice"
)

//go:embed web/dist
var embeddedFiles embed.FS

var Version = "dev"

func main() {
	cfg, err := config.Load("vane.db")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	pfManager := portforward.NewManager(cfg)
	ddnsManager := ddns.NewManager(cfg)
	wsManager := webservice.NewManager(cfg)
	tlsManager := tls.NewManager(cfg)

	pfManager.StartAll()
	ddnsManager.StartAll()
	wsManager.StartAll()
	tlsManager.StartAutoRenew()

	if os.Getenv("VANE_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// ── CORS ────────────────────────────────────────────────────────────────
	// Derive allowed origin from the admin port at startup. Admins can also
	// set VANE_ORIGIN env to an explicit origin (e.g. https://example.com:4455).
	allowedOrigin := os.Getenv("VANE_ORIGIN")
	if allowedOrigin == "" {
		cfg.RLock()
		allowedOrigin = fmt.Sprintf("http://localhost:%d", cfg.Admin.Port)
		cfg.RUnlock()
	}
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{allowedOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: false, // tokens are in the Authorization header, not cookies
	}))

	apiHandler := api.NewHandler(cfg, pfManager, ddnsManager, wsManager, tlsManager)
	apiHandler.Register(r)

	r.Use(api.SafeEntryMiddleware(cfg))

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		cfg.RLock()
		entry := cfg.Admin.SafeEntry
		cfg.RUnlock()

		if entry != "" {
			prefix := "/" + strings.Trim(entry, "/")
			if strings.HasPrefix(path, prefix) {
				path = strings.TrimPrefix(path, prefix)
				if path == "" {
					path = "/"
				}
			}
		}

		filePath := strings.TrimPrefix(path, "/")
		if filePath == "" {
			filePath = "index.html"
		}

		data, err := embeddedFiles.ReadFile("web/dist/" + filePath)
		if err != nil {
			data, err = embeddedFiles.ReadFile("web/dist/index.html")
			if err != nil {
				c.String(500, "index.html not found")
				return
			}
			c.Data(200, "text/html; charset=utf-8", data)
			return
		}

		ext := filepath.Ext(filePath)
		ct := mime.TypeByExtension(ext)
		if ct == "" {
			ct = "application/octet-stream"
		}
		c.Data(200, ct, data)
	})

	cfg.RLock()
	port := cfg.Admin.Port
	entry := cfg.Admin.SafeEntry
	username := cfg.Admin.Username
	cfg.RUnlock()

	entryPath := ""
	if entry != "" {
		entryPath = "/" + entry
	}
	fmt.Printf("\n  ✨ Dashboard : http://0.0.0.0:%d%s\n  🔑 Username  : %s\n  🔒 Storage   : vane.db (AES-256-GCM encrypted)\n  📦 Version   : %s\n\n",
		port, entryPath, username, Version)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("🌀 Vane %s  →  http://%s", Version, addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func init() {
	_ = http.MethodGet
}

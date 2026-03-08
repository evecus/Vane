package main

import (
	"embed"
	"flag"
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
	// ── 0. Parse CLI flags ─────────────────────────────────────────────────
	var disableFlag string
	flag.StringVar(&disableFlag, "disable", "", "Comma-separated features to disable (e.g. systeminfo)")
	flag.Parse()

	disabled := map[string]bool{}
	for _, f := range strings.Split(disableFlag, ",") {
		f = strings.TrimSpace(strings.ToLower(f))
		if f != "" {
			disabled[f] = true
		}
	}
	disableSysinfo := disabled["systeminfo"]

	// ── 1. Init encrypted SQLite data directory ────────────────────────────
	dd, err := config.NewDataDir()
	if err != nil {
		log.Fatalf("Failed to init data directory: %v", err)
	}

	cfg, err := config.Load(dd)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	printBanner(cfg, dd)

	// ── 2. Start modules ───────────────────────────────────────────────────
	pfManager := portforward.NewManager(cfg)
	ddnsManager := ddns.NewManager(cfg)
	wsManager := webservice.NewManager(cfg)
	tlsManager := tls.NewManager(cfg)

	pfManager.StartAll()
	ddnsManager.StartAll()
	wsManager.StartAll()
	tlsManager.StartAutoRenew()

	// ── 3. HTTP admin server ───────────────────────────────────────────────
	if os.Getenv("VANE_DEBUG") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// CORS: restrict to same host by default
	allowedOrigin := os.Getenv("VANE_CORS_ORIGIN")
	if allowedOrigin == "" {
		allowedOrigin = fmt.Sprintf("http://0.0.0.0:%d", cfg.Admin.Port)
	}
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{allowedOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: false,
	}))

	apiHandler := api.NewHandler(cfg, pfManager, ddnsManager, wsManager, tlsManager, Version, disableSysinfo)
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

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Admin.Port)
	log.Printf("🌀 Vane %s  →  http://%s", Version, addr)
	log.Printf("📁 Data    →  %s/vane.db  (AES-256-GCM encrypted)", dd.Root)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func printBanner(cfg *config.Config, dd *config.DataDir) {
	entry := ""
	if cfg.Admin.SafeEntry != "" {
		entry = "/" + cfg.Admin.SafeEntry
	}
	fmt.Printf(`
  ✨ Dashboard : http://0.0.0.0:%d%s
  👤 Username  : %s
  📦 Version   : %s
  🔐 Storage   : SQLite + AES-256-GCM (%s/vane.db)
  🌐 Web Svcs  : HTTPS only (HTTP auto-redirects to HTTPS)

`, cfg.Admin.Port, entry, cfg.Admin.Username, Version, dd.Root)
}

func init() {
	_ = http.MethodGet
}

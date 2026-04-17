package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/evecus/vane/api"
	"github.com/evecus/vane/config"
	"github.com/evecus/vane/module/ddns"
	"github.com/evecus/vane/module/portforward"
	"github.com/evecus/vane/module/tls"
	"github.com/evecus/vane/module/webservice"
)

//go:embed web/dist
var embeddedFiles embed.FS

var Version = "dev"

func main() {
	// ── 0. Parse CLI flags ─────────────────────────────────────────────────
	var disableFlag string
	var configPath string // 新增：用于存储自定义配置路径

	flag.StringVar(&disableFlag, "disable", "", "Comma-separated features to disable (e.g. systeminfo)")
	// 新增 --config 参数定义
	flag.StringVar(&configPath, "config", "", "Custom path for data and configuration (default: ./data)")
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
	// 修改：将 configPath 传给 NewDataDir
	dd, err := config.NewDataDir(configPath)
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
	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard
	gin.DefaultErrorWriter = io.Discard

	r := gin.New()
	r.Use(gin.Recovery())

	// CORS 设置
	allowedOrigin := os.Getenv("VANE_CORS_ORIGIN")
	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: false,
	}
	if allowedOrigin != "" {
		corsConfig.AllowOrigins = []string{allowedOrigin}
	} else {
		corsConfig.AllowAllOrigins = true
	}
	r.Use(cors.New(corsConfig))

	apiHandler := api.NewHandler(cfg, pfManager, ddnsManager, wsManager, tlsManager, Version, disableSysinfo)
	api.InitSessions(dd.DB())
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
	log.Printf("Vane %s  →  http://%s", Version, addr)
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

`, cfg.Admin.Port, entry, cfg.Admin.Username, Version, dd.Root)
}

func init() {
	_ = http.MethodGet
}

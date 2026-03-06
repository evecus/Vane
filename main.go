package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
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

// Version is injected by the build via -ldflags
var Version = "dev"

func main() {
	cfg, err := config.Load("vane.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	printBanner(cfg)

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
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
	}))

	// Register API routes
	apiHandler := api.NewHandler(cfg, pfManager, ddnsManager, wsManager, tlsManager)
	apiHandler.Register(r)

	// Embedded frontend
	distFS, err := fs.Sub(embeddedFiles, "web/dist")
	if err != nil {
		log.Fatalf("Failed to sub dist: %v", err)
	}

	// Safe-entry middleware for SPA
	r.Use(api.SafeEntryMiddleware(cfg))

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Strip safe-entry prefix before resolving asset
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

		rfs, ok := distFS.(fs.ReadFileFS)
		if path == "/" || path == "" || !ok {
			c.FileFromFS("index.html", http.FS(distFS))
			return
		}
		if _, err := rfs.ReadFile(strings.TrimPrefix(path, "/")); err != nil {
			c.FileFromFS("index.html", http.FS(distFS))
			return
		}
		c.FileFromFS(strings.TrimPrefix(path, "/"), http.FS(distFS))
	})

	addr := fmt.Sprintf("0.0.0.0:%d", cfg.Admin.Port)
	log.Printf("🌀 Vane %s  →  http://%s", Version, addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func printBanner(cfg *config.Config) {
	entry := ""
	if cfg.Admin.SafeEntry != "" {
		entry = "/" + cfg.Admin.SafeEntry
	}
	fmt.Printf(`
 ██╗   ██╗ █████╗ ███╗   ██╗███████╗
 ██║   ██║██╔══██╗████╗  ██║██╔════╝
 ██║   ██║███████║██╔██╗ ██║█████╗
 ╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══╝
  ╚████╔╝ ██║  ██║██║ ╚████║███████╗
   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝

  ✨ Dashboard : http://0.0.0.0:%d%s
  🔑 Login     : %s / admin
  📦 Version   : %s

`, cfg.Admin.Port, entry, cfg.Admin.Username, Version)
}

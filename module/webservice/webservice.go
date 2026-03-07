// Package webservice manages HTTPS reverse-proxy services.
// HTTPS is mandatory. Each service binds:
//   - ListenPort        → TLS (HTTPS) server
//   - ListenPort+10000  → plain HTTP redirect server (301 → https://host:ListenPort/…)
//
// If ListenPort+10000 exceeds 65535, the redirect listener is skipped.
package webservice

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/vane/config"
)

// ── Access log ring-buffer ────────────────────────────────────────────────────

const maxLogs = 2000

type LogStore struct {
	mu   sync.Mutex
	logs []config.WebAccessLog
}

var globalLogs = &LogStore{}

func (s *LogStore) Add(l config.WebAccessLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, l)
	if len(s.logs) > maxLogs {
		s.logs = s.logs[len(s.logs)-maxLogs:]
	}
}

func (s *LogStore) List(serviceID string, limit int) []config.WebAccessLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]config.WebAccessLog, 0, limit)
	for i := len(s.logs) - 1; i >= 0 && len(result) < limit; i-- {
		if serviceID == "" || s.logs[i].ServiceID == serviceID {
			result = append(result, s.logs[i])
		}
	}
	return result
}

func GetLogs() *LogStore { return globalLogs }

// ── responseRecorder ──────────────────────────────────────────────────────────

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ── Manager ───────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	servers map[string]*managedServer
}

type managedServer struct {
	httpsSrv    *http.Server // TLS – the real proxy
	redirectSrv *http.Server // plain HTTP → HTTPS redirect
}

func (ms *managedServer) close() {
	if ms.httpsSrv != nil {
		_ = ms.httpsSrv.Close()
	}
	if ms.redirectSrv != nil {
		_ = ms.redirectSrv.Close()
	}
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, servers: make(map[string]*managedServer)}
}

func (m *Manager) StartAll() {
	m.cfg.RLock()
	svcs := make([]config.WebService, len(m.cfg.WebServices))
	copy(svcs, m.cfg.WebServices)
	m.cfg.RUnlock()

	for _, svc := range svcs {
		if svc.Enabled {
			if err := m.Start(svc.ID); err != nil {
				log.Printf("[webservice] start %s error: %v", svc.ID, err)
			}
		}
	}
}

// Start starts the HTTPS server and the companion HTTP→HTTPS redirect server
// for a given service ID. Returns an error if no valid TLS cert is found.
func (m *Manager) Start(id string) error {
	m.cfg.RLock()
	var svc *config.WebService
	for i := range m.cfg.WebServices {
		if m.cfg.WebServices[i].ID == id {
			s := m.cfg.WebServices[i]
			svc = &s
			break
		}
	}
	m.cfg.RUnlock()
	if svc == nil {
		return fmt.Errorf("service %s not found", id)
	}

	// TLS cert is mandatory
	if svc.TLSCertID == "" {
		return fmt.Errorf("service %q has no TLS cert configured – HTTPS is required", svc.Name)
	}
	certPEM, keyPEM := m.getCertPEM(svc.TLSCertID)
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("service %q: TLS cert %s not found or empty", svc.Name, svc.TLSCertID)
	}
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("service %q: TLS load error: %w", svc.Name, err)
	}

	// Stop any existing instance
	m.mu.Lock()
	if old, ok := m.servers[id]; ok {
		old.close()
		delete(m.servers, id)
	}
	m.mu.Unlock()

	ms := &managedServer{}
	router := m.buildRouter(svc)

	// ── HTTPS server (ListenPort) ────────────────────────────────────────────
	httpsAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
	ms.httpsSrv = &http.Server{
		Addr:    httpsAddr,
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		log.Printf("[webservice] HTTPS :%d  (%s)", svc.ListenPort, svc.Name)
		if err := ms.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[webservice] HTTPS :%d error: %v", svc.ListenPort, err)
		}
	}()

	// ── HTTP redirect server (ListenPort + 10000) ────────────────────────────
	// Redirects plain HTTP → https://<host>:<ListenPort><path>
	redirectPort := svc.ListenPort + 10000
	if redirectPort <= 65535 {
		httpsPort := svc.ListenPort
		redirectAddr := fmt.Sprintf("0.0.0.0:%d", redirectPort)
		ms.redirectSrv = &http.Server{
			Addr: redirectAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				// Strip port from host if present, then re-attach the HTTPS port
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				target := fmt.Sprintf("https://%s:%d%s", host, httpsPort, r.RequestURI)
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("[webservice] HTTP redirect :%d → https:/<host>:%d  (%s)", redirectPort, httpsPort, svc.Name)
			if err := ms.redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[webservice] redirect :%d error: %v", redirectPort, err)
			}
		}()
	} else {
		log.Printf("[webservice] %s: redirect port %d out of range, HTTP redirect disabled", svc.Name, redirectPort)
	}

	m.mu.Lock()
	m.servers[id] = ms
	m.mu.Unlock()
	return nil
}

func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ms, ok := m.servers[id]; ok {
		ms.close()
		delete(m.servers, id)
	}
}

// ── Router ────────────────────────────────────────────────────────────────────

func (m *Manager) buildRouter(svc *config.WebService) http.Handler {
	type entry struct {
		route config.WebRoute
		proxy *httputil.ReverseProxy
	}

	entries := make([]entry, 0, len(svc.Routes))
	for _, route := range svc.Routes {
		if !route.Enabled {
			continue
		}
		target, err := url.Parse(route.BackendURL)
		if err != nil {
			log.Printf("[webservice] invalid backend %q: %v", route.BackendURL, err)
			continue
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		orig := proxy.Director
		proxy.Director = func(req *http.Request) {
			orig(req)
			req.Host = target.Host
		}
		entries = append(entries, entry{route: route, proxy: proxy})
	}

	svcID := svc.ID
	svcPort := svc.ListenPort

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip port from Host header
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		start := time.Now()
		rr := &responseRecorder{ResponseWriter: w, status: 200}

		for _, e := range entries {
			routeDomain := strings.TrimPrefix(e.route.Domain, "www.")
			reqDomain := strings.TrimPrefix(host, "www.")
			if strings.EqualFold(routeDomain, reqDomain) {
				e.proxy.ServeHTTP(rr, r)
				logAccess(svcID, e.route.ID, e.route.Domain, svcPort, r, rr.status, time.Since(start))
				return
			}
		}

		http.Error(w, "No matching route for host: "+host, http.StatusBadGateway)
		logAccess(svcID, "", host, svcPort, r, http.StatusBadGateway, time.Since(start))
	})
}

// ── Access log ────────────────────────────────────────────────────────────────

func logAccess(svcID, routeID, domain string, port int, r *http.Request, status int, dur time.Duration) {
	// Use direct TCP address; only promote X-Forwarded-For when coming from loopback
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if isLoopback(clientIP) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if first := strings.TrimSpace(strings.Split(fwd, ",")[0]); first != "" {
				clientIP = first
			}
		}
	}

	globalLogs.Add(config.WebAccessLog{
		ID:         config.NewID(),
		ServiceID:  svcID,
		RouteID:    routeID,
		Domain:     domain,
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: status,
		DurationMs: dur.Milliseconds(),
		ClientIP:   clientIP,
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
		Time:       config.Now(),
	})
}

func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

// ── Cert lookup ───────────────────────────────────────────────────────────────

func (m *Manager) getCertPEM(certID string) (cert, key string) {
	m.cfg.RLock()
	defer m.cfg.RUnlock()
	for _, c := range m.cfg.TLSCerts {
		if c.ID == certID {
			return c.CertPEM, c.KeyPEM
		}
	}
	return "", ""
}

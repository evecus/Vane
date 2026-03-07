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

// ─── Access log store (in-memory ring buffer, 2000 entries) ──────────────────

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

// ─── responseRecorder ────────────────────────────────────────────────────────

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	servers map[string]*managedServer
}

type managedServer struct {
	httpsSrv    *http.Server // main HTTPS server on listen_port
	redirectSrv *http.Server // HTTP→HTTPS redirect on listen_port-1 (or 80 if port==443)
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

// Start launches a web service. All services are HTTPS-only.
// A companion HTTP server on the redirect port automatically issues 301→HTTPS.
// If no valid TLS cert is configured, Start returns an error — HTTP fallback is intentionally removed.
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

	// Stop any existing instance first
	m.mu.Lock()
	if old, ok := m.servers[id]; ok {
		old.close()
		delete(m.servers, id)
	}
	m.mu.Unlock()

	// Require a valid TLS certificate — no HTTP-only fallback
	certPEM, keyPEM := m.getCertPEM(svc.TLSCertID)
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("service %q requires a TLS certificate but none is configured or the cert has not been issued yet", svc.Name)
	}
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("invalid TLS certificate for service %q: %w", svc.Name, err)
	}

	ms := &managedServer{}
	router := m.buildRouter(svc)

	// ── HTTPS server on listen_port ──
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
		log.Printf("[webservice] HTTPS :%d  (service %q)", svc.ListenPort, svc.Name)
		if err := ms.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[webservice] HTTPS :%d error: %v", svc.ListenPort, err)
		}
	}()

	// ── HTTP redirect companion ──
	// Convention: if HTTPS is on 443 → redirect from 80
	//             if HTTPS is on any other port → redirect from that port - 1
	//             (operator should configure their firewall/NAT accordingly)
	redirectPort := svc.ListenPort - 1
	if svc.ListenPort == 443 {
		redirectPort = 80
	}
	httpsPort := svc.ListenPort
	redirectAddr := fmt.Sprintf("0.0.0.0:%d", redirectPort)
	ms.redirectSrv = &http.Server{
		Addr: redirectAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			// Strip port if present, then re-attach HTTPS port (only if non-standard)
			hostName := host
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostName = h
			}
			var target string
			if httpsPort == 443 {
				target = "https://" + hostName + r.RequestURI
			} else {
				target = fmt.Sprintf("https://%s:%d%s", hostName, httpsPort, r.RequestURI)
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("[webservice] HTTP→HTTPS redirect :%d → :%d  (service %q)", redirectPort, httpsPort, svc.Name)
		if err := ms.redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[webservice] redirect :%d error: %v", redirectPort, err)
		}
	}()

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

// buildRouter creates an http.Handler that dispatches by Host header.
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
		// Suppress noisy upstream error logs for broken pipes
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[webservice] proxy error %s: %v", r.URL, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
		entries = append(entries, entry{route: route, proxy: proxy})
	}

	svcID := svc.ID

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				logAccess(svcID, e.route.ID, e.route.Domain, r, rr.status, time.Since(start))
				return
			}
		}

		http.Error(w, "No matching route for host: "+host, http.StatusBadGateway)
		logAccess(svcID, "", host, r, http.StatusBadGateway, time.Since(start))
	})
}

// logAccess records one access. Client IP is derived from the TCP connection
// only — X-Forwarded-For and X-Real-IP are never trusted to prevent spoofing.
func logAccess(svcID, routeID, domain string, r *http.Request, status int, dur time.Duration) {
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = ip
	}
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}
	globalLogs.Add(config.WebAccessLog{
		ID:         config.NewID(),
		ServiceID:  svcID,
		RouteID:    routeID,
		Domain:     domain,
		Method:     r.Method,
		Path:       path,
		StatusCode: status,
		DurationMs: dur.Milliseconds(),
		ClientIP:   clientIP,
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
		Time:       config.Now(),
	})
}

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

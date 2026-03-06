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

// ─── responseRecorder wraps ResponseWriter to capture status code & size ─────

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
	httpSrv  *http.Server
	httpsSrv *http.Server
}

func (ms *managedServer) close() {
	if ms.httpSrv != nil {
		_ = ms.httpSrv.Close()
	}
	if ms.httpsSrv != nil {
		_ = ms.httpsSrv.Close()
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

	m.mu.Lock()
	if old, ok := m.servers[id]; ok {
		old.close()
		delete(m.servers, id)
	}
	m.mu.Unlock()

	ms := &managedServer{}

	// Build the routing handler (domain → backend)
	router := m.buildRouter(svc)

	if svc.EnableHTTPS {
		// Load TLS cert
		cert, key := m.getCertPEM(svc.TLSCertID)

		// HTTP server: redirect everything to HTTPS
		httpAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
		ms.httpSrv = &http.Server{
			Addr: httpAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}),
		}

		// HTTPS server
		httpsAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
		if cert != "" && key != "" {
			tlsCert, err := tls.X509KeyPair([]byte(cert), []byte(key))
			if err != nil {
				log.Printf("[webservice] TLS load error for %s: %v", id, err)
			} else {
				ms.httpsSrv = &http.Server{
					Addr:      httpsAddr,
					Handler:   router,
					TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
				}
				// For HTTPS we actually need two ports unless using ALPN.
				// Since we can't bind both HTTP and HTTPS to the same port easily,
				// we bind HTTPS on the configured port and HTTP on port+1 for redirect.
				// OR: use a single listener that detects TLS via first byte.
				// Simplest approach: serve HTTPS directly; HTTP redirect on port 80 if port is 443,
				// otherwise just serve HTTPS only.
				go func() {
					log.Printf("[webservice] HTTPS :%d (service %s)", svc.ListenPort, svc.Name)
					if err := ms.httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
						log.Printf("[webservice] HTTPS error: %v", err)
					}
				}()
				m.mu.Lock()
				m.servers[id] = ms
				m.mu.Unlock()
				return nil
			}
		}
		// Fall through to plain HTTP if no cert
	}

	// Plain HTTP server
	httpAddr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
	ms.httpSrv = &http.Server{Addr: httpAddr, Handler: router}
	go func() {
		log.Printf("[webservice] HTTP :%d (service %s)", svc.ListenPort, svc.Name)
		if err := ms.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[webservice] HTTP error: %v", err)
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
		route   config.WebRoute
		proxy   *httputil.ReverseProxy
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
		// Preserve the original host header
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

		// Find matching route
		for _, e := range entries {
			routeDomain := strings.TrimPrefix(e.route.Domain, "www.")
			reqDomain := strings.TrimPrefix(host, "www.")
			if strings.EqualFold(routeDomain, reqDomain) {
				e.proxy.ServeHTTP(rr, r)
				logAccess(svcID, e.route.ID, e.route.Domain, svcPort, r, rr.status, time.Since(start))
				return
			}
		}

		// No match
		http.Error(w, "No matching route for host: "+host, http.StatusBadGateway)
		logAccess(svcID, "", host, svcPort, r, http.StatusBadGateway, time.Since(start))
	})
}

func logAccess(svcID, routeID, domain string, port int, r *http.Request, status int, dur time.Duration) {
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = ip
	}
	// Try X-Forwarded-For
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		clientIP = strings.Split(fwd, ",")[0]
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		clientIP = real
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

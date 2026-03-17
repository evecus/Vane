package webservice

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourusername/vane/config"
	"golang.org/x/crypto/bcrypt"
)

// validateBackendURL checks that the backend URL has a valid http/https scheme.
// Local and private addresses are intentionally allowed — the web service is
// a reverse proxy configured by the admin, and proxying to local services
// (e.g. http://127.0.0.1:8080) is a primary use case.
func validateBackendURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("backend URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("backend URL has no host")
	}
	return nil
}

// ─── Access log store ─────────────────────────────────────────────────────────

const maxLogs = 2000

type LogStore struct {
	mu   sync.Mutex
	logs []config.WebAccessLog
}

var globalLogs = &LogStore{}

func (s *LogStore) Add(l config.WebAccessLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Auto-clear logs from previous days — keep only today's entries
	today := time.Now().Format("2006-01-02")
	filtered := s.logs[:0]
	for _, existing := range s.logs {
		if len(existing.Time) >= 10 && existing.Time[:10] == today {
			filtered = append(filtered, existing)
		}
	}
	s.logs = append(filtered, l)
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

// ─── 协议嗅探：单端口同时支持 HTTP 和 HTTPS ───────────────────────────────────
//
// 原理：TCP 连接建立后，偷看第一个字节。
//   0x16 = TLS ClientHello → 走 TLS 握手
//   其他  = 明文 HTTP       → 直接回复 301 重定向到 HTTPS

type peekConn struct {
	net.Conn
	r io.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type sniffListener struct {
	net.Listener
	httpCh chan net.Conn
	tlsCh  chan net.Conn
	done   chan struct{}
}

func newSniffListener(inner net.Listener) *sniffListener {
	sl := &sniffListener{
		Listener: inner,
		httpCh:   make(chan net.Conn, 64),
		tlsCh:    make(chan net.Conn, 64),
		done:     make(chan struct{}),
	}
	go sl.dispatch()
	return sl
}

func (sl *sniffListener) dispatch() {
	for {
		conn, err := sl.Listener.Accept()
		if err != nil {
			select {
			case <-sl.done:
			default:
				log.Printf("[webservice] accept error: %v", err)
			}
			// 关闭两个 channel，让 chanListener.Accept() 退出
			close(sl.httpCh)
			close(sl.tlsCh)
			return
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			b, err := br.Peek(1)
			if err != nil {
				c.Close()
				return
			}
			pc := &peekConn{Conn: c, r: br}
			if b[0] == 0x16 { // TLS ClientHello
				sl.tlsCh <- pc
			} else {
				sl.httpCh <- pc
			}
		}(conn)
	}
}

func (sl *sniffListener) close() {
	select {
	case <-sl.done:
	default:
		close(sl.done)
	}
	sl.Listener.Close()
}

// chanListener 把 chan net.Conn 包装成 net.Listener
type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

func newChanListener(ch chan net.Conn, addr net.Addr) *chanListener {
	return &chanListener{ch: ch, addr: addr, closed: make(chan struct{})}
}

func (cl *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-cl.ch:
		if !ok {
			return nil, fmt.Errorf("listener closed")
		}
		return c, nil
	case <-cl.closed:
		return nil, fmt.Errorf("listener closed")
	}
}

func (cl *chanListener) Close() error {
	cl.once.Do(func() { close(cl.closed) })
	return nil
}

func (cl *chanListener) Addr() net.Addr { return cl.addr }

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	servers map[string]*managedServer
}

type managedServer struct {
	sniff     *sniffListener
	httpSrv   *http.Server
	httpsSrv  *http.Server
	http80Srv *http.Server // optional :80 → HTTPS redirect server
	httpLn    *chanListener
	httpsLn   *chanListener
	// certMap is updated atomically whenever certificates change — no restart needed.
	// Holds a map[string]tls.Certificate keyed by lowercase domain/wildcard.
	certMap atomic.Value // stores map[string]tls.Certificate
}

func (ms *managedServer) loadCertMap() map[string]tls.Certificate {
	v := ms.certMap.Load()
	if v == nil {
		return map[string]tls.Certificate{}
	}
	return v.(map[string]tls.Certificate)
}

func (ms *managedServer) storeCertMap(m map[string]tls.Certificate) {
	ms.certMap.Store(m)
}

func (ms *managedServer) close() {
	if ms.httpSrv != nil {
		_ = ms.httpSrv.Close()
	}
	if ms.httpsSrv != nil {
		_ = ms.httpsSrv.Close()
	}
	if ms.http80Srv != nil {
		_ = ms.http80Srv.Close()
	}
	if ms.httpLn != nil {
		_ = ms.httpLn.Close()
	}
	if ms.httpsLn != nil {
		_ = ms.httpsLn.Close()
	}
	if ms.sniff != nil {
		ms.sniff.close()
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

// Start 根据服务配置启动 HTTP 或 HTTP+HTTPS。
// 若 EnableHTTPS=true：单端口嗅探，HTTP 自动 301 重定向至 HTTPS，HTTPS 正常反代。
// 若 EnableHTTPS=false：单端口纯 HTTP 反代，无 TLS。
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

	// 先停掉旧实例
	m.mu.Lock()
	if old, ok := m.servers[id]; ok {
		old.close()
		delete(m.servers, id)
	}
	m.mu.Unlock()

	addr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)

	// ── 纯 HTTP 模式 ──────────────────────────────────────────────────────────
	if !svc.EnableHTTPS {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		router := m.buildRouter(svc)
		httpSrv := &http.Server{
			Handler:      router,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		ms := &managedServer{
			httpSrv: httpSrv,
			httpLn:  newChanListener(make(chan net.Conn), ln.Addr()), // placeholder
		}
		// 直接用原始 listener，不走 sniff
		go func() {
			log.Printf("[webservice] HTTP :%d  (service %q)", svc.ListenPort, svc.Name)
			if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[webservice] HTTP error: %v", err)
			}
		}()
		m.mu.Lock()
		m.servers[id] = ms
		m.mu.Unlock()
		return nil
	}

	// ── HTTPS 模式（含 HTTP→HTTPS 重定向）────────────────────────────────────
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	sl := newSniffListener(ln)
	httpLn := newChanListener(sl.httpCh, ln.Addr())
	httpsLn := newChanListener(sl.tlsCh, ln.Addr())

	ms := &managedServer{
		sniff:   sl,
		httpLn:  httpLn,
		httpsLn: httpsLn,
	}
	// Store initial certMap (may be empty if certs not yet issued — will be hot-updated)
	ms.storeCertMap(m.buildCertMap(svc))

	httpsPort := svc.ListenPort

	// HTTP server：收到明文请求，301 → https://host:port/path
	ms.httpSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
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
		log.Printf("[webservice] HTTP→HTTPS redirect on :%d  (service %q)", httpsPort, svc.Name)
		if err := ms.httpSrv.Serve(httpLn); err != nil && err.Error() != "listener closed" {
			log.Printf("[webservice] HTTP redirect error: %v", err)
		}
	}()

	// HTTPS server：查预构建的 certMap，O(1)
	router := m.buildRouter(svc)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certMap := ms.loadCertMap()
			serverName := strings.ToLower(hello.ServerName)
			if c, ok := certMap[serverName]; ok {
				return &c, nil
			}
			// 通配符回退
			parts := strings.SplitN(serverName, ".", 2)
			if len(parts) == 2 {
				wildcard := "*." + parts[1]
				if c, ok := certMap[wildcard]; ok {
					return &c, nil
				}
			}
			// 兜底取第一个
			for _, c := range certMap {
				cc := c
				return &cc, nil
			}
			return nil, fmt.Errorf("no certificate available for %q", hello.ServerName)
		},
	}
	ms.httpsSrv = &http.Server{
		Handler:      router,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		log.Printf("[webservice] HTTPS :%d  (service %q)", httpsPort, svc.Name)
		tlsLn := tls.NewListener(httpsLn, tlsCfg)
		if err := ms.httpsSrv.Serve(tlsLn); err != nil && err != http.ErrServerClosed && err.Error() != "listener closed" {
			log.Printf("[webservice] HTTPS error: %v", err)
		}
	}()

	m.mu.Lock()
	m.servers[id] = ms
	m.mu.Unlock()

	// 监听 :80 自动跳转 HTTPS（仅 443 端口时生效）
	if httpsPort == 443 {
		ln80, err := net.Listen("tcp", "0.0.0.0:80")
		if err != nil {
			log.Printf("[webservice] :80 redirect unavailable (port busy): %v", err)
		} else {
			srv80 := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					if h, _, err := net.SplitHostPort(host); err == nil {
						host = h
					}
					http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
				}),
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			ms.http80Srv = srv80
			go func() {
				log.Printf("[webservice] :80 → :443 HTTPS redirect  (service %q)", svc.Name)
				if err := srv80.Serve(ln80); err != nil && err != http.ErrServerClosed {
					log.Printf("[webservice] :80 redirect error: %v", err)
				}
			}()
		}
	}

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

// buildRouter 按 Host header 分发到对应后端。
// 路由表在每次请求时从 config 动态读取，无需重启服务即可感知新增/修改/删除的路由。
// ReverseProxy 实例按 backendURL 缓存在 proxyCache 中避免重复创建。
func (m *Manager) buildRouter(svc *config.WebService) http.Handler {
	svcID := svc.ID
	var proxyCache sync.Map // key: backendURL string → *httputil.ReverseProxy

	getProxy := func(backendURL string) (*httputil.ReverseProxy, error) {
		if v, ok := proxyCache.Load(backendURL); ok {
			return v.(*httputil.ReverseProxy), nil
		}
		target, err := url.Parse(backendURL)
		if err != nil {
			return nil, err
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Director = func(req *http.Request) {
			// Set backend scheme and path, but preserve the original Host header
			// so the backend app generates correct URLs and redirects.
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			if target.Path != "" {
				req.URL.Path = target.Path + req.URL.Path
			}
			// Standard reverse-proxy headers
			clientIP := req.RemoteAddr
			if ip, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = ip
			}
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				clientIP = prior + ", " + clientIP
			}
			req.Header.Set("X-Forwarded-For", clientIP)
			req.Header.Set("X-Real-IP", clientIP)
			if req.TLS != nil || svc.EnableHTTPS {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
			// Delete hop-by-hop headers
			req.Header.Del("Te")
			req.Header.Del("Trailers")
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[webservice] proxy error %s: %v", r.URL, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
		proxyCache.Store(backendURL, proxy)
		return proxy, nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		// Dynamically read current routes from config on every request
		m.cfg.RLock()
		var matchedRoute *config.WebRoute
		var matchedBackend string
		for _, ws := range m.cfg.WebServices {
			if ws.ID != svcID {
				continue
			}
			for _, route := range ws.Routes {
				if !route.Enabled {
					continue
				}
				routeDomain := strings.TrimPrefix(strings.ToLower(route.Domain), "www.")
				reqDomain := strings.TrimPrefix(strings.ToLower(host), "www.")
				if routeDomain == reqDomain {
					r := route
					matchedRoute = &r
					matchedBackend = route.BackendURL
					break
				}
			}
			break
		}
		m.cfg.RUnlock()

		if matchedRoute == nil {
			log.Printf("[webservice] no matching route for host: %s (svc %s)", host, svcID)
			http.Error(w, "No matching route for host: "+host, http.StatusBadGateway)
			logAccess(svcID, "", "", host, r)
			return
		}

		if err := validateBackendURL(matchedBackend); err != nil {
			log.Printf("[webservice] invalid backend %q: %v", matchedBackend, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			logAccess(svcID, matchedRoute.ID, matchedRoute.Name, matchedRoute.Domain, r)
			return
		}

		proxy, err := getProxy(matchedBackend)
		if err != nil {
			log.Printf("[webservice] parse backend %q: %v", matchedBackend, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			logAccess(svcID, matchedRoute.ID, matchedRoute.Name, matchedRoute.Domain, r)
			return
		}

		rr := &responseRecorder{ResponseWriter: w, status: 200}

		// Basic Auth check with session cookie to avoid repeated prompts
		if matchedRoute.AuthEnabled && matchedRoute.AuthPassHash != "" {
			cookieName := "vane_auth_" + matchedRoute.ID[:8]
			sessionToken := authSessionToken(matchedRoute.ID, matchedRoute.AuthPassHash)
			if cookie, err := r.Cookie(cookieName); err != nil || cookie.Value != sessionToken {
				user, pass, ok := r.BasicAuth()
				if !ok || user != matchedRoute.AuthUser || bcrypt.CompareHashAndPassword([]byte(matchedRoute.AuthPassHash), []byte(pass)) != nil {
					w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					logAccess(svcID, matchedRoute.ID, matchedRoute.Name, matchedRoute.Domain, r)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName,
					Value:    sessionToken,
					Path:     "/",
					MaxAge:   7 * 24 * 3600,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}

		proxy.ServeHTTP(rr, r)
		logAccess(svcID, matchedRoute.ID, matchedRoute.Name, matchedRoute.Domain, r)
	})
}

func logAccess(svcID, routeID, routeName, domain string, r *http.Request) {
	clientIP := r.RemoteAddr
	if ip, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = ip
	}
	ua := r.UserAgent()
	browser := parseBrowser(ua)

	// Deduplicate: only record if no existing entry today with same IP + UA + routeID
	globalLogs.mu.Lock()
	today := time.Now().Format("2006-01-02")
	for i := len(globalLogs.logs) - 1; i >= 0; i-- {
		l := globalLogs.logs[i]
		if len(l.Time) < 10 {
			continue
		}
		if l.Time[:10] < today {
			break
		}
		if l.RouteID == routeID && l.ClientIP == clientIP && l.UserAgent == ua {
			globalLogs.mu.Unlock()
			return
		}
	}
	globalLogs.mu.Unlock()
	globalLogs.Add(config.WebAccessLog{
		ID:        config.NewID(),
		ServiceID: svcID,
		RouteID:   routeID,
		RouteName: routeName,
		Domain:    domain,
		ClientIP:  clientIP,
		UserAgent: browser,
		Time:      config.Now(),
	})
}

// parseBrowser extracts a short browser/OS label from a User-Agent string.
func parseBrowser(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edge/"):
		return "Edge"
	case strings.Contains(ua, "chrome") && strings.Contains(ua, "mobile"):
		return "Chrome/Android"
	case strings.Contains(ua, "chrome"):
		return "Chrome"
	case strings.Contains(ua, "firefox"):
		return "Firefox"
	case strings.Contains(ua, "safari") && strings.Contains(ua, "mobile"):
		return "Safari/iOS"
	case strings.Contains(ua, "safari"):
		return "Safari"
	case strings.Contains(ua, "curl"):
		return "curl"
	case strings.Contains(ua, "wget"):
		return "wget"
	case ua == "":
		return "—"
	default:
		return "Other"
	}
}

// getService returns a copy of the WebService with the given ID, or nil.
func (m *Manager) getService(id string) *config.WebService {
	m.cfg.RLock()
	defer m.cfg.RUnlock()
	for i := range m.cfg.WebServices {
		if m.cfg.WebServices[i].ID == id {
			s := m.cfg.WebServices[i]
			return &s
		}
	}
	return nil
}

// buildCertMap builds a map of domain → tls.Certificate for all enabled routes
// that have a matched cert. Called once at service startup; result cached in managedServer.
func (m *Manager) buildCertMap(svc *config.WebService) map[string]tls.Certificate {
	if svc == nil {
		return nil
	}
	m.cfg.RLock()
	defer m.cfg.RUnlock()
	result := map[string]tls.Certificate{}
	for _, route := range svc.Routes {
		if !route.Enabled || route.MatchedCertID == "" {
			continue
		}
		for _, cert := range m.cfg.TLSCerts {
			if cert.ID == route.MatchedCertID && cert.CertPEM != "" && cert.KeyPEM != "" {
				tlsCert, err := tls.X509KeyPair([]byte(cert.CertPEM), []byte(cert.KeyPEM))
				if err != nil {
					continue
				}
				result[strings.ToLower(route.Domain)] = tlsCert
				break
			}
		}
	}
	return result
}

// MatchRouteCert finds the best matching active certificate for a single route
// and updates the route's MatchedCertID and CertStatus in-memory and in DB.
// svcID is needed to persist the route.
func (m *Manager) MatchRouteCert(svcID string, route *config.WebRoute) {
	m.cfg.RLock()
	certs := make([]config.TLSCert, len(m.cfg.TLSCerts))
	copy(certs, m.cfg.TLSCerts)
	m.cfg.RUnlock()

	bestID := ""
	bestStatus := "no_cert"

	for _, cert := range certs {
		if cert.CertPEM == "" || cert.KeyPEM == "" {
			continue
		}
		certDomains := append([]string{}, cert.Domains...)
		if cert.Domain != "" {
			certDomains = append(certDomains, cert.Domain)
		}
		matched := false
		for _, cd := range certDomains {
			if certDomainMatches(cd, route.Domain) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// Found a matching cert — prefer active
		if cert.Status == "active" {
			bestID = cert.ID
			bestStatus = "ok"
			break
		} else if bestID == "" {
			// Keep as fallback (inactive match)
			bestID = cert.ID
			bestStatus = "cert_inactive"
		}
	}

	m.cfg.Lock()
	for i := range m.cfg.WebServices {
		if m.cfg.WebServices[i].ID == svcID {
			for j := range m.cfg.WebServices[i].Routes {
				if m.cfg.WebServices[i].Routes[j].ID == route.ID {
					m.cfg.WebServices[i].Routes[j].MatchedCertID = bestID
					m.cfg.WebServices[i].Routes[j].CertStatus = bestStatus
					*route = m.cfg.WebServices[i].Routes[j]
					break
				}
			}
			break
		}
	}
	m.cfg.Unlock()
	_ = m.cfg.SaveWebRoute(svcID, *route)
}

// RematchAllRoutes re-runs cert matching for every route across all services.
// Called when a certificate is added, updated, or deleted.
func (m *Manager) RematchAllRoutes() {
	m.cfg.RLock()
	type svcRoute struct {
		svcID string
		route config.WebRoute
	}
	var pairs []svcRoute
	for _, svc := range m.cfg.WebServices {
		for _, route := range svc.Routes {
			pairs = append(pairs, svcRoute{svcID: svc.ID, route: route})
		}
	}
	m.cfg.RUnlock()

	for i := range pairs {
		r := pairs[i].route
		m.MatchRouteCert(pairs[i].svcID, &r)
	}

	// Hot-reload certMap for every running HTTPS service — no restart needed.
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ms := range m.servers {
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
		if svc != nil && svc.EnableHTTPS {
			ms.storeCertMap(m.buildCertMap(svc))
		}
	}
}

// certDomainMatches 判断证书域名（支持泛域名 *.example.com）是否覆盖请求域名。
func certDomainMatches(certDomain, reqDomain string) bool {
	certDomain = strings.ToLower(strings.TrimSpace(certDomain))
	reqDomain = strings.ToLower(strings.TrimSpace(reqDomain))
	if certDomain == reqDomain {
		return true
	}
	// 泛域名匹配：*.example.com 覆盖 foo.example.com
	if strings.HasPrefix(certDomain, "*.") {
		suffix := certDomain[1:] // .example.com
		if strings.HasSuffix(reqDomain, suffix) {
			// 确保只匹配一级，如 *.a.com 不匹配 b.c.a.com
			host := reqDomain[:len(reqDomain)-len(suffix)]
			if !strings.Contains(host, ".") {
				return true
			}
		}
	}
	return false
}

// authSessionToken generates a deterministic session token from the route ID and password hash.
// Changing the password invalidates all existing sessions automatically.
func authSessionToken(routeID, passHash string) string {
	mac := hmac.New(sha256.New, []byte(passHash))
	mac.Write([]byte(routeID))
	return hex.EncodeToString(mac.Sum(nil))
}

package webservice

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
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
	httpLn    *chanListener
	httpsLn   *chanListener
}

func (ms *managedServer) close() {
	if ms.httpSrv != nil {
		_ = ms.httpSrv.Close()
	}
	if ms.httpsSrv != nil {
		_ = ms.httpsSrv.Close()
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

// Start 在单个端口上同时监听 HTTP 和 HTTPS。
// HTTP 请求自动 301 重定向到 https://同域名:同端口。
// 没有证书则拒绝启动。
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

	// 必须有有效证书
	certPEM, keyPEM := m.getCertPEM(svc.TLSCertID)
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("service %q requires a TLS certificate but none is configured or issued yet", svc.Name)
	}
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("invalid TLS certificate for service %q: %w", svc.Name, err)
	}

	// 绑定端口
	addr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
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

	httpsPort := svc.ListenPort

	// ── HTTP server：收到明文请求，301 → https://host:port/path ──
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

	// ── HTTPS server：TLS 连接，正常反代 ──
	router := m.buildRouter(svc)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
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
		// ServeTLS 的第2/3参数传空字符串，证书已在 TLSConfig 里
		tlsLn := tls.NewListener(httpsLn, tlsCfg)
		if err := ms.httpsSrv.Serve(tlsLn); err != nil && err != http.ErrServerClosed && err.Error() != "listener closed" {
			log.Printf("[webservice] HTTPS error: %v", err)
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

// buildRouter 按 Host header 分发到对应后端
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

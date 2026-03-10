package portforward

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourusername/vane/config"
)

// ─── Stats ───────────────────────────────────────────────────────────────────

type Stats struct {
	BytesIn  atomic.Int64
	BytesOut atomic.Int64
	Conns    atomic.Int64
}

func (s *Stats) Snapshot() StatSnapshot {
	return StatSnapshot{
		BytesIn:  s.BytesIn.Load(),
		BytesOut: s.BytesOut.Load(),
		Conns:    s.Conns.Load(),
	}
}

type StatSnapshot struct {
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Conns    int64     `json:"conns"`
	Time     time.Time `json:"time"`
}

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	workers map[string][]*worker // one rule may spawn two workers (tcp+udp)
	stats   map[string]*Stats
	history map[string][]StatSnapshot
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:     cfg,
		workers: make(map[string][]*worker),
		stats:   make(map[string]*Stats),
		history: make(map[string][]StatSnapshot),
	}
}

func (m *Manager) StartAll() {
	m.cfg.RLock()
	rules := make([]config.PortForwardRule, len(m.cfg.PortForwards))
	copy(rules, m.cfg.PortForwards)
	m.cfg.RUnlock()

	for _, r := range rules {
		if r.Enabled {
			if err := m.Start(r.ID); err != nil {
				log.Printf("[portforward] start %s error: %v", r.ID, err)
			}
		}
	}
	go m.collectStats()
}

func (m *Manager) Start(id string) error {
	m.cfg.RLock()
	var rule *config.PortForwardRule
	for i := range m.cfg.PortForwards {
		if m.cfg.PortForwards[i].ID == id {
			r := m.cfg.PortForwards[i]
			rule = &r
			break
		}
	}
	m.cfg.RUnlock()
	if rule == nil {
		return fmt.Errorf("rule %s not found", id)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing workers for this rule
	for _, w := range m.workers[id] {
		w.stop()
	}
	delete(m.workers, id)

	st := &Stats{}
	m.stats[id] = st

	var protocols []string
	switch rule.Protocol {
	case "both":
		protocols = []string{"tcp", "udp"}
	case "udp":
		protocols = []string{"udp"}
	default:
		protocols = []string{"tcp"}
	}

	var ws []*worker
	for _, proto := range protocols {
		w := newWorker(*rule, proto, st)
		ws = append(ws, w)
		go w.run()
	}
	m.workers[id] = ws
	return nil
}

func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, w := range m.workers[id] {
		w.stop()
	}
	delete(m.workers, id)
}

func (m *Manager) GetStats(id string) *Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats[id]
}

func (m *Manager) GetHistory(id string) []StatSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.history[id]
	result := make([]StatSnapshot, len(h))
	copy(result, h)
	return result
}

func (m *Manager) collectStats() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		m.mu.Lock()
		for id, st := range m.stats {
			snap := st.Snapshot()
			snap.Time = time.Now()
			h := m.history[id]
			h = append(h, snap)
			if len(h) > 360 {
				h = h[len(h)-360:]
			}
			m.history[id] = h
		}
		m.mu.Unlock()
	}
}

// ─── Worker ──────────────────────────────────────────────────────────────────

type worker struct {
	rule     config.PortForwardRule
	proto    string // "tcp" or "udp"
	stats    *Stats
	stopCh   chan struct{}
	listener net.Listener
	udpConn  *net.UDPConn
}

func newWorker(rule config.PortForwardRule, proto string, stats *Stats) *worker {
	return &worker{rule: rule, proto: proto, stats: stats, stopCh: make(chan struct{})}
}

func (w *worker) stop() {
	close(w.stopCh)
	if w.listener != nil {
		_ = w.listener.Close()
	}
	if w.udpConn != nil {
		_ = w.udpConn.Close()
	}
}

func (w *worker) run() {
	if w.proto == "udp" {
		w.runUDP()
	} else {
		w.runTCP()
	}
}

func (w *worker) runTCP() {
	addr := fmt.Sprintf("0.0.0.0:%d", w.rule.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[portforward] TCP listen %s error: %v", addr, err)
		return
	}
	w.listener = ln
	log.Printf("[portforward] TCP %s → %s:%d", addr, w.rule.TargetIP, w.rule.TargetPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-w.stopCh:
				return
			default:
				continue
			}
		}
		w.stats.Conns.Add(1)
		go w.handleTCP(conn)
	}
}

func (w *worker) handleTCP(src net.Conn) {
	defer src.Close()
	defer w.stats.Conns.Add(-1)

	target := fmt.Sprintf("%s:%d", w.rule.TargetIP, w.rule.TargetPort)
	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[portforward] TCP dial %s error: %v", target, err)
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(dst, src)
		w.stats.BytesIn.Add(n)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(src, dst)
		w.stats.BytesOut.Add(n)
	}()
	wg.Wait()
}

func (w *worker) runUDP() {
	addr := fmt.Sprintf("0.0.0.0:%d", w.rule.ListenPort)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("[portforward] UDP resolve %s error: %v", addr, err)
		return
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Printf("[portforward] UDP listen %s error: %v", addr, err)
		return
	}
	w.udpConn = conn
	log.Printf("[portforward] UDP %s → %s:%d", addr, w.rule.TargetIP, w.rule.TargetPort)

	target := fmt.Sprintf("%s:%d", w.rule.TargetIP, w.rule.TargetPort)
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("[portforward] UDP resolve target %s error: %v", target, err)
		return
	}

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-w.stopCh:
				return
			default:
				continue
			}
		}
		w.stats.BytesIn.Add(int64(n))
		go w.handleUDP(conn, clientAddr, raddr, buf[:n])
	}
}

func (w *worker) handleUDP(src *net.UDPConn, clientAddr, targetAddr *net.UDPAddr, data []byte) {
	dst, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer dst.Close()

	if _, err := dst.Write(data); err != nil {
		return
	}

	resp := make([]byte, 65535)
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := dst.Read(resp)
	if err != nil {
		return
	}
	w.stats.BytesOut.Add(int64(n))
	_, _ = src.WriteToUDP(resp[:n], clientAddr)
}

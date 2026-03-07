package ddns

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/vane/config"
)

// ─── Manager ──────────────────────────────────────────────────────────────────

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	workers map[string]*Worker
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, workers: make(map[string]*Worker)}
}

func (m *Manager) StartAll() {
	m.cfg.RLock()
	rules := make([]config.DDNSRule, len(m.cfg.DDNS))
	copy(rules, m.cfg.DDNS)
	m.cfg.RUnlock()

	for _, r := range rules {
		if r.Enabled {
			m.Start(r.ID)
		}
	}
}

func (m *Manager) Start(id string) {
	m.cfg.RLock()
	var rule *config.DDNSRule
	for i := range m.cfg.DDNS {
		if m.cfg.DDNS[i].ID == id {
			r := m.cfg.DDNS[i]
			rule = &r
			break
		}
	}
	m.cfg.RUnlock()
	if rule == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.workers[id]; ok {
		w.Stop()
	}
	w := newWorker(*rule, m.cfg)
	m.workers[id] = w
	go w.Run()
}

func (m *Manager) Stop(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.workers[id]; ok {
		w.Stop()
		delete(m.workers, id)
	}
}

// ─── Worker ───────────────────────────────────────────────────────────────────

type Worker struct {
	rule   config.DDNSRule
	cfg    *config.Config
	stopCh chan struct{}
}

func newWorker(rule config.DDNSRule, cfg *config.Config) *Worker {
	return &Worker{rule: rule, cfg: cfg, stopCh: make(chan struct{})}
}

func (w *Worker) Stop() { close(w.stopCh) }

func (w *Worker) Run() {
	interval := time.Duration(w.rule.Interval) * time.Second
	if interval < 60*time.Second {
		interval = 300 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	w.check() // run immediately
	for {
		select {
		case <-ticker.C:
			w.check()
		case <-w.stopCh:
			return
		}
	}
}

func (w *Worker) check() {
	ip, err := getPublicIP(w.rule.IPVersion)
	if err != nil {
		log.Printf("[ddns] %s: get IP error: %v", w.rule.Domain, err)
		return
	}

	if ip == w.rule.LastIP {
		return
	}

	log.Printf("[ddns] %s: IP changed %s → %s", w.rule.Domain, w.rule.LastIP, ip)

	var updateErr error
	switch w.rule.Provider {
	case "cloudflare":
		updateErr = updateCloudflare(w.rule, ip)
	case "alidns":
		updateErr = updateAliDNS(w.rule, ip)
	case "dnspod", "tencentcloud":
		updateErr = updateDNSPod(w.rule, ip)
	default:
		log.Printf("[ddns] unknown provider: %s", w.rule.Provider)
		return
	}

	if updateErr != nil {
		log.Printf("[ddns] %s: update error: %v", w.rule.Domain, updateErr)
		return
	}

	// Persist
	w.cfg.Lock()
	for i := range w.cfg.DDNS {
		if w.cfg.DDNS[i].ID == w.rule.ID {
			w.cfg.DDNS[i].LastIP = ip
			w.cfg.DDNS[i].LastUpdated = config.Now()
			w.cfg.DDNS[i].IPHistory = append(w.cfg.DDNS[i].IPHistory, config.IPRecord{
				IP:        ip,
				Timestamp: config.Now(),
			})
			if len(w.cfg.DDNS[i].IPHistory) > 100 {
				w.cfg.DDNS[i].IPHistory = w.cfg.DDNS[i].IPHistory[len(w.cfg.DDNS[i].IPHistory)-100:]
			}
			w.rule = w.cfg.DDNS[i]
			break
		}
	}
	w.cfg.Unlock()
	_ = w.cfg.Save()
}

// ─── Public IP ────────────────────────────────────────────────────────────────

func getPublicIP(version string) (string, error) {
	urls := []string{"https://api4.ipify.org", "https://4.ipw.cn"}
	if version == "ipv6" {
		urls = []string{"https://api6.ipify.org", "https://6.ipw.cn"}
	}
	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(b))
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("all IP detection endpoints failed")
}

// ─── Cloudflare ───────────────────────────────────────────────────────────────

func updateCloudflare(rule config.DDNSRule, ip string) error {
	token := rule.ProviderConf.APIToken
	zoneID := rule.ProviderConf.ZoneID
	fqdn := rule.SubDomain + "." + rule.Domain
	if rule.SubDomain == "@" || rule.SubDomain == "" {
		fqdn = rule.Domain
	}

	// List DNS records
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", zoneID, fqdn)
	req, _ := http.NewRequest("GET", listURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var listResp struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return err
	}

	recType := "A"
	if rule.IPVersion == "ipv6" {
		recType = "AAAA"
	}

	body := fmt.Sprintf(`{"type":"%s","name":"%s","content":"%s","ttl":60,"proxied":false}`, recType, fqdn, ip)

	if len(listResp.Result) > 0 {
		recordID := listResp.Result[0].ID
		putURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
		req2, _ := http.NewRequest("PUT", putURL, strings.NewReader(body))
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		if err != nil {
			return err
		}
		resp2.Body.Close()
	} else {
		postURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
		req2, _ := http.NewRequest("POST", postURL, strings.NewReader(body))
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		if err != nil {
			return err
		}
		resp2.Body.Close()
	}
	return nil
}

// ─── AliDNS ───────────────────────────────────────────────────────────────────

func updateAliDNS(rule config.DDNSRule, ip string) error {
	// Aliyun DNS API via alidns SDK style HTTP call
	// Simplified: use the public alidns endpoint
	log.Printf("[ddns] AliDNS update %s → %s (stub, implement with aliyun-go-sdk)", rule.Domain, ip)
	return nil
}

// ─── DNSPod / TencentCloud ────────────────────────────────────────────────────

func updateDNSPod(rule config.DDNSRule, ip string) error {
	log.Printf("[ddns] DNSPod update %s → %s (stub, implement with dnspod API)", rule.Domain, ip)
	return nil
}

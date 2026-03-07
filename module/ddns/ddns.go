package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
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
	ip, err := getPublicIP(w.rule.IPVersion, w.rule.IPDetectMode, w.rule.IPInterface, w.rule.IPIndex)
	if err != nil {
		log.Printf("[ddns] rule %s: get IP error: %v", w.rule.Name, err)
		return
	}

	if ip == w.rule.LastIP {
		return
	}

	log.Printf("[ddns] rule %s: IP changed %s → %s", w.rule.Name, w.rule.LastIP, ip)

	// Resolve effective domain list (support legacy single Domain+SubDomain)
	domains := w.rule.Domains
	if len(domains) == 0 && w.rule.Domain != "" {
		fqdn := w.rule.Domain
		if w.rule.SubDomain != "" && w.rule.SubDomain != "@" {
			fqdn = w.rule.SubDomain + "." + w.rule.Domain
		}
		domains = []string{fqdn}
	}

	// Update each domain
	for _, fqdn := range domains {
		var updateErr error
		switch w.rule.Provider {
		case "cloudflare":
			updateErr = updateCloudflareRecord(w.rule, fqdn, ip)
		case "alidns":
			updateErr = updateAliDNSRecord(w.rule, fqdn, ip)
		case "dnspod", "tencentcloud":
			updateErr = updateDNSPodRecord(w.rule, fqdn, ip)
		default:
			log.Printf("[ddns] unknown provider: %s", w.rule.Provider)
			return
		}
		if updateErr != nil {
			log.Printf("[ddns] rule %s fqdn %s: update error: %v", w.rule.Name, fqdn, updateErr)
		}
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


// ─── Public IP Detection ──────────────────────────────────────────────────────

// IP extraction regexes — same approach as ddns-go: scan the full response body
// so any response format (plain text, JSON, HTML) works.
var (
	ipv4Reg = regexp.MustCompile(`((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`)
	ipv6Reg = regexp.MustCompile(`(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|` +
		`([0-9A-Fa-f]{1,4}:){1,7}:|` +
		`([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|` +
		`([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}|` +
		`([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}|` +
		`([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}|` +
		`([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}|` +
		`[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,6}|` +
		`:(:[0-9A-Fa-f]{1,4}){1,7})`)
)

// noProxyClient follows ddns-go's strategy: force tcp4 or tcp6 at the dialer level.
// This ensures we use the correct address family and bypass any system proxy.
var noProxyDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 0}

func noProxyClient(version string) *http.Client {
	network := "tcp4"
	if version == "ipv6" {
		network = "tcp6"
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return noProxyDialer.DialContext(ctx, network, address)
			},
		},
	}
}

// getPublicIP returns the machine's public IP.
// mode: "api"   → query external service (proxy-free, forced tcp4/tcp6)
//       "iface" → read IP from named network interface
func getPublicIP(version, mode, iface string, ipIndex int) (string, error) {
	if mode == "iface" && iface != "" {
		ip, err := getIPFromInterface(iface, version, ipIndex)
		if err == nil {
			return ip, nil
		}
		log.Printf("[ddns] iface %s read failed (%v), falling back to API", iface, err)
	}
	return getPublicIPViaAPI(version)
}

// getPublicIPViaAPI queries external endpoints with forced tcp4/tcp6 (no proxy).
// Uses regex extraction — works with plain text, JSON, or HTML responses.
func getPublicIPViaAPI(version string) (string, error) {
	client := noProxyClient(version)
	reg := ipv4Reg
	urls := []string{
		"https://ipv4.icanhazip.com",
		"https://api4.ipify.org",
		"https://v4.ident.me",
		"https://api4.ipify.org",
		"https://4.ipw.cn",
	}
	if version == "ipv6" {
		reg = ipv6Reg
		urls = []string{
			"https://ipv6.icanhazip.com",
			"https://api6.ipify.org",
			"https://v6.ident.me",
			"https://api-ipv6.ip.sb/ip",
			"https://api6.ipify.org",
			"https://6.ipw.cn",
		}
	}
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ddns] API %s failed: %v", u, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		ip := reg.FindString(string(body))
		if ip != "" {
			log.Printf("[ddns] got %s from %s: %s", version, u, ip)
			return ip, nil
		}
		log.Printf("[ddns] %s returned no valid IP, body: %.80s", u, string(body))
	}
	return "", fmt.Errorf("all %s IP detection endpoints failed", version)
}

// getIPFromInterface reads a suitable IP from a named network interface.
// ipIndex: for IPv6, selects the Nth global unicast address (0 = first).
func getIPFromInterface(ifaceName, version string, ipIndex int) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	wantV6 := version == "ipv6"
	var candidates []string
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() && !wantV6 {
			continue
		}
		isV6 := ip.To4() == nil
		if isV6 != wantV6 {
			continue
		}
		// For IPv6 skip private/ULA (fc00::/7) — keep only global unicast
		if wantV6 && (ip[0]&0xfe) == 0xfc {
			continue
		}
		candidates = append(candidates, ip.String())
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no suitable %s address on interface %s", version, ifaceName)
	}
	if ipIndex < 0 || ipIndex >= len(candidates) {
		ipIndex = 0
	}
	return candidates[ipIndex], nil
}

// ListInterfaceIPs returns all suitable IPs on an interface for the given version.
// Used by the API to let the user preview which addresses are available.
func ListInterfaceIPs(ifaceName, version string) ([]string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	wantV6 := version == "ipv6"
	var result []string
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		isV6 := ip.To4() == nil
		if isV6 != wantV6 {
			continue
		}
		if wantV6 && (ip[0]&0xfe) == 0xfc {
			continue // skip ULA
		}
		result = append(result, ip.String())
	}
	return result, nil
}


// ─── Cloudflare ───────────────────────────────────────────────────────────────

// cfDo is a small helper that executes a Cloudflare API request and checks success.
func cfDo(client *http.Client, method, url, token, body string) error {
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r struct {
		Success bool            `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return err
	}
	if !r.Success && len(r.Errors) > 0 {
		return fmt.Errorf("cloudflare API error: %s", r.Errors[0].Message)
	}
	return nil
}

// cfResolveZoneID returns the provided zoneID if non-empty, otherwise
// queries the Cloudflare API to find the Zone ID for the root domain of fqdn.
func cfResolveZoneID(client *http.Client, token, zoneID, fqdn string) (string, error) {
	if zoneID != "" {
		return zoneID, nil
	}
	// Extract root domain (last two labels) from fqdn for zone lookup
	parts := strings.Split(fqdn, ".")
	rootDomain := fqdn
	if len(parts) >= 2 {
		rootDomain = strings.Join(parts[len(parts)-2:], ".")
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", rootDomain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if len(r.Result) == 0 {
		return "", fmt.Errorf("cloudflare: no zone found for domain %s", rootDomain)
	}
	return r.Result[0].ID, nil
}

func updateCloudflareRecord(rule config.DDNSRule, fqdn, ip string) error {
	token := rule.ProviderConf.APIToken
	client := &http.Client{Timeout: 15 * time.Second}

	// Zone ID is optional — auto-resolve from domain if blank
	zoneID, err := cfResolveZoneID(client, token, rule.ProviderConf.ZoneID, fqdn)
	if err != nil {
		return fmt.Errorf("zone ID lookup failed: %w", err)
	}

	recType := "A"
	if rule.IPVersion == "ipv6" {
		recType = "AAAA"
	}

	// Find existing DNS record
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=%s&name=%s", zoneID, recType, fqdn)
	req, _ := http.NewRequest("GET", listURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
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

	body := fmt.Sprintf(`{"type":%q,"name":%q,"content":%q,"ttl":60,"proxied":false}`, recType, fqdn, ip)

	if len(listResp.Result) > 0 {
		recordID := listResp.Result[0].ID
		putURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
		return cfDo(client, "PUT", putURL, token, body)
	}
	postURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	return cfDo(client, "POST", postURL, token, body)
}

// ─── AliDNS ───────────────────────────────────────────────────────────────────

func updateAliDNSRecord(rule config.DDNSRule, fqdn, ip string) error {
	// Aliyun DNS API via alidns SDK style HTTP call
	// Simplified: use the public alidns endpoint
	log.Printf("[ddns] AliDNS update %s → %s (stub, implement with aliyun-go-sdk)", rule.Domain, ip)
	return nil
}

// ─── DNSPod / TencentCloud ────────────────────────────────────────────────────

func updateDNSPodRecord(rule config.DDNSRule, fqdn, ip string) error {
	log.Printf("[ddns] DNSPod update %s → %s (stub, implement with dnspod API)", rule.Domain, ip)
	return nil
}

// GetInterfaces returns only physical network interface names.
//
// Detection strategy (Linux):
//   /sys/class/net/<iface>/device  exists  → backed by a real hardware device (PCI/USB/etc.)
//   /sys/class/net/<iface>/wireless exists → Wi-Fi physical interface
//
// Both are physical; everything else (veth, bridge, tun, sit, docker…) lacks the
// "device" symlink and is therefore considered virtual.
//
// On non-Linux platforms we fall back to the name-prefix heuristic so the code
// still compiles and runs (e.g. macOS in development).
func GetInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !isPhysicalInterface(iface.Name) {
			continue
		}
		names = append(names, iface.Name)
	}
	return names
}

// isPhysicalInterface returns true when the named interface corresponds to a
// real hardware NIC. On Linux this is determined by the presence of the
// /sys/class/net/<name>/device sysfs entry, which the kernel only creates for
// interfaces that are bound to an actual hardware device.
func isPhysicalInterface(name string) bool {
	// Primary check: sysfs device symlink (Linux only)
	devicePath := "/sys/class/net/" + name + "/device"
	if _, err := os.Stat(devicePath); err == nil {
		return true // has a hardware device → physical
	}
	// Wireless interfaces always have a "wireless" directory under sysfs
	wirelessPath := "/sys/class/net/" + name + "/wireless"
	if _, err := os.Stat(wirelessPath); err == nil {
		return true
	}
	// Fallback for non-Linux (development): exclude obvious virtual prefixes
	virtualPrefixes := []string{
		"veth", "docker", "br-", "virbr", "vmnet", "vboxnet",
		"tun", "tap", "sit", "ip6tnl", "gre", "dummy", "lo",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	// On non-Linux, if it passed the prefix check assume physical
	return true
}

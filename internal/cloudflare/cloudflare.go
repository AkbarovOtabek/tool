// Package cloudflare определяет, стоит ли цель за Cloudflare, и пытается найти
// и ПОДТВЕРДИТЬ реальный IP origin-сервера (легитимный приём для авторизованного
// теста: WAF маскирует настоящий хост, тестировать нужно именно его).
//
// Источники кандидатов origin: пассивно crt.sh + резолв, а при наличии ключей —
// Shodan (поиск по hostname/сертификату) и SecurityTrails (история A-записей).
// Каждый кандидат активно проверяется: запрос напрямую на IP с подменой Host —
// если ответ совпадает с сайтом за WAF, origin подтверждён.
package cloudflare

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/store"
)

// Диапазоны Cloudflare (IPv4). Источник: https://www.cloudflare.com/ips-v4
var cfCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

var cfNets []*net.IPNet

func init() {
	for _, c := range cfCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			cfNets = append(cfNets, n)
		}
	}
}

// IsCloudflareIP сообщает, принадлежит ли IP диапазонам Cloudflare.
func IsCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range cfNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

var resolver = &net.Resolver{}

func resolve(ctx context.Context, host string) []string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(cctx, host)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			out = append(out, ip)
		}
	}
	return out
}

// Run проверяет домены скоупа на Cloudflare и ищет+подтверждает origin.
func Run(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink, candidates []string) {
	behindCF := false
	for _, d := range sc.Domains() {
		for _, ip := range resolve(ctx, d) {
			if IsCloudflareIP(ip) {
				behindCF = true
				st.Add(store.Finding{Target: d, Type: store.TypeCloudflare, Severity: store.SevInfo,
					Title: "Домен за Cloudflare (" + ip + ")", Detail: "обычный скан бьёт по WAF, не по origin", Tool: "pentkit"})
			}
		}
	}
	if !behindCF {
		ev.Logln("  Cloudflare на корневых доменах не обнаружен")
		return
	}
	ev.Logln("  обнаружен Cloudflare — ищу origin...")

	// 1. Набираем хосты-кандидаты: переданные + crt.sh.
	hostSet := map[string]bool{}
	for _, h := range candidates {
		hostSet[strings.ToLower(h)] = true
	}
	for _, d := range sc.Domains() {
		for _, h := range crtshSubdomains(ctx, d) {
			if sc.InScope(h) {
				hostSet[strings.ToLower(h)] = true
			}
		}
	}

	// 2. Кандидаты-IP: резолв хостов (вне диапазонов CF) + Shodan + SecurityTrails.
	candIPs := map[string][]string{} // ip -> источники/хосты
	for h := range hostSet {
		for _, ip := range resolve(ctx, h) {
			if !IsCloudflareIP(ip) && !isPrivate(ip) {
				candIPs[ip] = append(candIPs[ip], h)
			}
		}
	}
	addCand := func(ip, src string) {
		if !IsCloudflareIP(ip) && !isPrivate(ip) {
			candIPs[ip] = append(candIPs[ip], src)
		}
	}
	for _, d := range sc.Domains() {
		if cfg.Keys.Shodan != "" {
			for _, ip := range shodanOrigins(ctx, cfg.Keys.Shodan, d) {
				addCand(ip, "shodan:"+d)
			}
			// favicon-hash: хосты с тем же фавиконом (частый способ найти origin).
			for _, ip := range faviconHashOrigins(ctx, cfg.Keys.Shodan, d) {
				addCand(ip, "favicon:"+d)
			}
		}
		if cfg.Keys.SecurityTrails != "" {
			for _, ip := range securityTrailsHistory(ctx, cfg.Keys.SecurityTrails, d) {
				addCand(ip, "securitytrails:"+d)
			}
		}
		if cfg.Keys.Censys != "" {
			for _, ip := range censysOrigins(ctx, cfg.Keys.Censys, d) {
				addCand(ip, "censys:"+d)
			}
		}
		// SPF/MX — пассивно, без ключей: IP почтовой/смежной инфраструктуры вне CF.
		for _, ip := range spfMXOrigins(ctx, d) {
			addCand(ip, "spf/mx:"+d)
		}
	}

	ips := make([]string, 0, len(candIPs))
	for ip := range candIPs {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	if len(ips) == 0 {
		ev.Logln("  origin в обход CF не найден (добавь ключи Shodan/SecurityTrails в конфиг для глубже)")
		return
	}
	// Пассивный режим: не стучимся напрямую к origin (это активный запрос),
	// только фиксируем кандидатов из пассивных источников для ручной проверки.
	if rn.Passive {
		ev.Logf("  пассивный режим: %d кандидатов origin без активной проверки\n", len(ips))
		for _, ip := range ips {
			st.Add(store.Finding{Target: ip, Type: store.TypeOrigin, Severity: store.SevLow,
				Title:    "Кандидат origin (пассивно): " + ip,
				Detail:   "источники: " + strings.Join(dedupSort(candIPs[ip]), ", "),
				Evidence: "IP вне диапазонов CF, связан с хостами в скоупе; проверь вручную",
				Tool:     "pentkit", Tags: []string{"cloudflare-bypass", "passive"}})
		}
		return
	}
	ev.Logf("  кандидатов origin: %d — проверяю напрямую (подмена Host)...\n", len(ips))

	// 3. Эталон: как выглядит сайт через WAF (по первому домену).
	domains := sc.Domains()
	baseTitle, baseLen, _ := fetchVia(ctx, "https://"+domains[0], domains[0], "", rn.SOCKS)

	confirmed := 0
	for _, ip := range ips {
		hosts := dedupSort(candIPs[ip])
		title, length, ok := fetchVia(ctx, "https://"+domains[0], domains[0], ip, rn.SOCKS)
		switch {
		case ok && originMatches(baseTitle, baseLen, title, length):
			confirmed++
			st.Add(store.Finding{Target: ip, Type: store.TypeOrigin, Severity: store.SevHigh,
				Title:    "ПОДТВЕРЖДЁН origin в обход Cloudflare: " + ip,
				Detail:   "источники: " + strings.Join(hosts, ", "),
				Evidence: "прямой запрос с Host: " + domains[0] + " отдал тот же сайт (title/размер совпали) — WAF можно обойти",
				Tool:     "pentkit", Tags: []string{"cloudflare-bypass", "origin-confirmed"}})
			ev.Logf("  ✔ origin подтверждён: %s\n", ip)
		case ok:
			st.Add(store.Finding{Target: ip, Type: store.TypeOrigin, Severity: store.SevMedium,
				Title:    "Кандидат origin (отвечает напрямую): " + ip,
				Detail:   "источники: " + strings.Join(hosts, ", "),
				Evidence: "IP отвечает на прямой запрос, но контент не совпал с сайтом за WAF — проверь вручную",
				Tool:     "pentkit", Tags: []string{"cloudflare-bypass", "requires-review"}})
		default:
			st.Add(store.Finding{Target: ip, Type: store.TypeOrigin, Severity: store.SevLow,
				Title:    "Возможный origin (пассивно): " + ip,
				Detail:   "источники: " + strings.Join(hosts, ", "),
				Evidence: "IP вне диапазонов CF, связан с хостами в скоупе; прямой ответ не получен",
				Tool:     "pentkit", Tags: []string{"cloudflare-bypass"}})
		}
	}
	ev.Logf("  origin: кандидатов %d, подтверждено %d\n", len(ips), confirmed)
	ev.Logln("  ручная проверка: curl -H 'Host: <домен>' --resolve <домен>:443:<origin-ip> https://<домен> -k")
}

// fetchVia делает GET url; если forceIP задан — соединяется именно с этим IP,
// подменяя адрес, но сохраняя Host из url (так достукиваемся до origin за CF).
// Возвращает заголовок страницы, размер тела и признак успеха.
func fetchVia(ctx context.Context, rawurl, host, forceIP, socks string) (string, int, bool) {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: host},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections() // не копим соединения при переборе кандидатов
	// Подменяем адрес назначения на origin-IP (forceIP), сохраняя Host.
	// Через SOCKS (Tor) просим прокси соединиться с этим IP — так достукиваемся
	// до origin в обход CF, не светя свой адрес.
	switch {
	case socks != "":
		sd := netx.NewDialer(socks, 10*time.Second)
		tr.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			if forceIP != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					port = "443"
				}
				addr = net.JoinHostPort(forceIP, port)
			}
			return sd.DialContext(c, network, addr)
		}
	case forceIP != "":
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		tr.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "443"
			}
			return dialer.DialContext(c, network, net.JoinHostPort(forceIP, port))
		}
	}
	client := &http.Client{Timeout: 12 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return "", 0, false
	}
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 pentkit")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if resp.StatusCode >= 500 {
		return "", 0, false
	}
	return extractTitle(string(body)), len(body), true
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(html string) string {
	m := titleRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// originMatches сравнивает ответ origin с эталоном за WAF.
func originMatches(baseTitle string, baseLen int, title string, length int) bool {
	if baseTitle != "" && title != "" && strings.EqualFold(baseTitle, title) {
		return true
	}
	if baseLen > 0 && length > 0 {
		diff := baseLen - length
		if diff < 0 {
			diff = -diff
		}
		if diff*100/baseLen <= 15 { // размер тела в пределах 15%
			return true
		}
	}
	return false
}

// shodanOrigins ищет IP, связанные с доменом, через Shodan.
func shodanOrigins(ctx context.Context, key, domain string) []string {
	q := url.Values{}
	q.Set("key", key)
	q.Set("query", "hostname:"+domain)
	u := "https://api.shodan.io/shodan/host/search?" + q.Encode()
	var body struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
		} `json:"matches"`
	}
	if !getJSON(ctx, u, nil, &body) {
		return nil
	}
	var out []string
	for _, m := range body.Matches {
		if m.IPStr != "" {
			out = append(out, m.IPStr)
		}
	}
	return out
}

// securityTrailsHistory тянет историю A-записей (старые origin до Cloudflare).
func securityTrailsHistory(ctx context.Context, key, domain string) []string {
	u := "https://api.securitytrails.com/v1/history/" + domain + "/dns/a"
	var body struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
		} `json:"records"`
	}
	if !getJSON(ctx, u, map[string]string{"APIKEY": key}, &body) {
		return nil
	}
	var out []string
	for _, r := range body.Records {
		for _, v := range r.Values {
			if v.IP != "" {
				out = append(out, v.IP)
			}
		}
	}
	return out
}

func getJSON(ctx context.Context, u string, headers map[string]string, v any) bool {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "pentkit-recon")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(v) == nil
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	return p == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()
}

func dedupSort(in []string) []string {
	set := map[string]bool{}
	var out []string
	for _, s := range in {
		if !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func crtshSubdomains(ctx context.Context, domain string) []string {
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	u := "https://crt.sh/?" + q.Encode()

	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "pentkit-recon")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if json.NewDecoder(resp.Body).Decode(&rows) != nil {
		return nil
	}
	set := map[string]bool{}
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "*.")))
			if name != "" {
				set[name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out
}

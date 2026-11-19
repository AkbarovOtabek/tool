// Package recon — этап разведки: поддомены -> резолв -> порты -> HTTP/технологии.
// Оркестрирует subfinder, dnsx, naabu, httpx. Все хосты фильтруются по scope.
package recon

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"pentkit/internal/analyze"
	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/store"
)

// Result — сводка recon для передачи дальше по пайплайну.
type Result struct {
	Subdomains []string          // все найденные поддомены в скоупе
	Resolved   map[string]string // host -> IP (A-запись)
	HTTP       []HTTPService     // живые HTTP(S)-сервисы
}

// URLs возвращает список URL живых сервисов.
func (r *Result) URLs() []string {
	var u []string
	for _, s := range r.HTTP {
		u = append(u, s.URL)
	}
	return u
}

// HTTPService — живой веб-сервис, найденный httpx.
type HTTPService struct {
	URL    string
	Host   string
	Status int
	Title  string
	Tech   []string
	Server string
	IP     string
}

type httpxLine struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
	Webserver  string   `json:"webserver"`
	A          []string `json:"a"`
}

// Run выполняет разведку по всем доменам скоупа.
func Run(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink) (*Result, error) {
	res := &Result{Resolved: map[string]string{}}
	subSet := map[string]bool{}
	var subMu sync.Mutex

	// 1. Поддомены (subfinder, пассивно) — домены обрабатываем параллельно:
	//    subfinder по каждому домену независим, незачем ждать их по очереди.
	if !rn.Has("subfinder") {
		ev.Logln("  ! subfinder не установлен — пропускаю перебор поддоменов")
	}
	var wgSub sync.WaitGroup
	for _, d := range sc.Domains() {
		subMu.Lock()
		subSet[d] = true
		subMu.Unlock()
		if !rn.Has("subfinder") {
			continue
		}
		wgSub.Add(1)
		go func(d string) {
			defer wgSub.Done()
			r := rn.Run(ctx, "subfinder", "-silent", "-d", d)
			if r.Err != nil {
				ev.Logf("  ! subfinder %s: %v\n", d, r.Err)
			}
			subMu.Lock()
			for _, h := range r.Lines {
				if sc.InScope(h) {
					subSet[strings.ToLower(h)] = true
				}
			}
			subMu.Unlock()
		}(d)
	}
	wgSub.Wait()
	// Пассивное расширение поверхности: amass + assetfinder + tlsx.
	for _, h := range analyze.ExtraSubdomains(ctx, rn, sc, ev, sc.Domains()) {
		subSet[strings.ToLower(h)] = true
	}
	// uncover (Shodan) — ещё хосты по ключу, если он задан.
	for _, h := range analyze.Uncover(ctx, cfg, sc, rn, st, ev, sc.Domains()) {
		subSet[strings.ToLower(h)] = true
	}
	for h := range subSet {
		res.Subdomains = append(res.Subdomains, h)
	}
	sort.Strings(res.Subdomains)
	// Находки по поддоменам добавляем НЕ здесь, а в конце (emitSubdomains) —
	// когда уже известна их живость (резолв + HTTP + TCP-проба).
	ev.Logf("  поддоменов в скоупе: %d\n", len(res.Subdomains))
	if len(res.Subdomains) == 0 {
		return res, nil
	}

	// 2. Резолв (dnsx).
	hostsBlob := strings.Join(res.Subdomains, "\n")
	live := res.Subdomains
	if rn.Has("dnsx") {
		r := rn.RunStdin(ctx, hostsBlob, "dnsx", "-silent", "-a", "-resp", "-json")
		var resolved []string
		for _, line := range r.Lines {
			var d struct {
				Host string   `json:"host"`
				A    []string `json:"a"`
			}
			if json.Unmarshal([]byte(line), &d) != nil || d.Host == "" {
				continue
			}
			resolved = append(resolved, d.Host)
			if len(d.A) > 0 {
				res.Resolved[d.Host] = d.A[0]
				st.Add(store.Finding{Target: d.Host, Type: store.TypeDNS, Severity: store.SevInfo,
					Title: "Резолвится в " + strings.Join(d.A, ", "), Tool: "dnsx"})
			}
		}
		if len(resolved) > 0 {
			live = resolved
		}
		ev.Logf("  резолвится хостов: %d\n", len(resolved))
	} else {
		ev.Logln("  ! dnsx не установлен — пропускаю резолв")
	}

	// 3. Порты (naabu). Копим порты по хостам — пригодятся для оценки живости.
	portsByHost := map[string][]int{}
	switch {
	case rn.Passive:
		ev.Logln("  пассивный режим: пропускаю скан портов (naabu) — слишком шумно для WAF/Firewall")
	case rn.Has("naabu"):
		naabuArgs := []string{"-silent", "-top-ports", "100", "-json"}
		if rn.Proxied() {
			// connect-скан: SYN-пакеты мимо proxychains утекли бы в обход Tor.
			naabuArgs = append(naabuArgs, "-s", "c")
		}
		if rn.Stealthy() {
			naabuArgs = append(naabuArgs, "-c", "10", "-retries", "1")
		}
		if cfg.RateLimit > 0 {
			naabuArgs = append(naabuArgs, "-rate", itoa(cfg.RateLimit))
		}
		r := rn.RunStdin(ctx, strings.Join(live, "\n"), "naabu", naabuArgs...)
		for _, line := range r.Lines {
			var p struct {
				Host string `json:"host"`
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}
			if json.Unmarshal([]byte(line), &p) != nil {
				continue
			}
			target := p.Host
			if target == "" {
				target = p.IP
			}
			if p.Host != "" {
				portsByHost[hostOnly(p.Host)] = append(portsByHost[hostOnly(p.Host)], p.Port)
			}
			st.Add(store.Finding{Target: target, Type: store.TypePort, Severity: store.SevInfo,
				Title: "Открыт порт " + itoa(p.Port), Detail: p.IP, Tool: "naabu"})
		}
	default:
		ev.Logln("  ! naabu не установлен — пропускаю скан портов")
	}

	// 4. HTTP + технологии (httpx).
	httpByHost := map[string]HTTPService{} // host (без порта) -> живой HTTP-сервис
	if rn.Has("httpx") {
		httpxArgs := []string{"-silent", "-json", "-title", "-tech-detect", "-status-code", "-web-server", "-a"}
		if rn.Stealthy() {
			// случайный User-Agent + мало потоков, чтобы пробы не выделялись
			// единой подписью и частотой (иначе WAF быстро банит по rate).
			httpxArgs = append(httpxArgs, "-random-agent", "-threads", "10")
		}
		if cfg.RateLimit > 0 {
			httpxArgs = append(httpxArgs, "-rate-limit", itoa(cfg.RateLimit))
		}
		r := rn.RunStdin(ctx, strings.Join(live, "\n"), "httpx", httpxArgs...)
		for _, line := range r.Lines {
			var h httpxLine
			if json.Unmarshal([]byte(line), &h) != nil || h.URL == "" {
				continue
			}
			svc := HTTPService{URL: h.URL, Host: h.Host, Status: h.StatusCode,
				Title: h.Title, Tech: h.Tech, Server: h.Webserver}
			if len(h.A) > 0 {
				svc.IP = h.A[0]
			}
			res.HTTP = append(res.HTTP, svc)
			if hn := hostOnly(h.Host); hn != "" {
				if _, ok := httpByHost[hn]; !ok {
					httpByHost[hn] = svc
				}
			}
			st.Add(store.Finding{Target: h.URL, Type: store.TypeHTTP, Severity: store.SevInfo,
				Title:  "HTTP " + itoa(h.StatusCode) + " — " + h.Title,
				Detail: "server: " + h.Webserver, Tool: "httpx"})
			for _, t := range h.Tech {
				st.Add(store.Finding{Target: h.URL, Type: store.TypeTech, Severity: store.SevInfo,
					Title: "Технология: " + t, Tool: "httpx"})
			}
		}
		ev.Logf("  живых HTTP-сервисов: %d\n", len(res.HTTP))
	} else {
		ev.Logln("  ! httpx не установлен — пропускаю HTTP-пробинг")
	}

	// 5. Классификация CDN/WAF (cdncheck) — чтобы знать, где фронт за CDN.
	cdnCheck(ctx, rn, st, ev, res)

	// 6. Живость поддоменов: пишем находку по каждому с явным статусом.
	if rn.SOCKS != "" {
		ev.Logln("  ⚠ трафик через Tor/SOCKS: определение живости и портов может быть ЗАНИЖЕНО (exit-ноды режут не-web порты, высокая задержка)")
	}
	emitSubdomains(ctx, rn, st, ev, res, httpByHost, portsByHost)

	return res, nil
}

// cdnCheck классифицирует резолвящиеся хосты как CDN/WAF/cloud (cdncheck).
func cdnCheck(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, res *Result) {
	if !rn.Has("cdncheck") || len(res.Resolved) == 0 {
		return
	}
	var hosts []string
	for h := range res.Resolved {
		hosts = append(hosts, h)
	}
	r := rn.RunStdin(ctx, strings.Join(hosts, "\n"), "cdncheck", "-json", "-silent")
	n := 0
	for _, line := range r.Lines {
		var d struct {
			Input   string `json:"input"`
			CDN     bool   `json:"cdn"`
			CDNName string `json:"cdn_name"`
			WAF     bool   `json:"waf"`
			WAFName string `json:"waf_name"`
		}
		if json.Unmarshal([]byte(line), &d) != nil || d.Input == "" {
			continue
		}
		var what, name string
		switch {
		case d.WAF:
			what, name = "WAF", d.WAFName
		case d.CDN:
			what, name = "CDN", d.CDNName
		default:
			continue
		}
		st.Add(store.Finding{Target: d.Input, Type: store.TypeTech, Severity: store.SevInfo,
			Title: "За " + what + ": " + name, Detail: "учти при тестировании (фронт за " + what + ")",
			Tool: "cdncheck", Tags: []string{strings.ToLower(what)}})
		n++
	}
	if n > 0 {
		ev.Logf("  cdncheck: за CDN/WAF хостов: %d\n", n)
	}
}

// emitSubdomains добавляет находку по каждому поддомену с явным признаком
// живости: отвечает по HTTP / открыт TCP-порт / только резолвится / мёртвый.
// Для хостов без HTTP-ответа делает лёгкую TCP-пробу 443 и 80 («пинг»).
func emitSubdomains(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, res *Result, httpByHost map[string]HTTPService, portsByHost map[string][]int) {
	var live, resolvesOnly, dead int
	// TCP-пробы распараллелим: это независимые короткие соединения.
	type probeRes struct {
		host string
		port string
	}
	sem := make(chan struct{}, 20)
	results := make(chan probeRes, len(res.Subdomains))
	var wg sync.WaitGroup

	for _, h := range res.Subdomains {
		if _, ok := httpByHost[h]; ok {
			continue // уже знаем, что жив по HTTP
		}
		if len(portsByHost[h]) > 0 {
			continue // naabu уже нашёл открытые порты — TCP-проба не нужна
		}
		if rn.Passive {
			continue // активная TCP-проба запрещена в пассивном режиме
		}
		if _, resolves := res.Resolved[h]; !resolves && len(res.Resolved) > 0 {
			continue // не резолвится — пробовать порты бессмысленно
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			if port := tcpAlive(ctx, rn, h); port != "" {
				results <- probeRes{h, port}
			}
		}(h)
	}
	go func() { wg.Wait(); close(results) }()
	tcpOpen := map[string]string{}
	for r := range results {
		tcpOpen[r.host] = r.port
	}

	for _, h := range res.Subdomains {
		var detail, status string
		var tags []string
		if svc, ok := httpByHost[h]; ok {
			status = "жив (HTTP)"
			detail = "HTTP " + itoa(svc.Status)
			if svc.Title != "" {
				detail += " — " + svc.Title
			}
			if svc.IP != "" {
				detail += " · " + svc.IP
			}
			tags = []string{"live", "http"}
			live++
		} else if ports := portsByHost[h]; len(ports) > 0 {
			status = "жив (порты)"
			detail = "открыты порты: " + joinPorts(ports)
			if ip := res.Resolved[h]; ip != "" {
				detail += " · " + ip
			}
			tags = []string{"live", "ports"}
			live++
		} else if port, ok := tcpOpen[h]; ok {
			status = "жив (TCP)"
			detail = "порт " + port + " открыт"
			if ip := res.Resolved[h]; ip != "" {
				detail += " · " + ip
			}
			detail += " (HTTP-баннера нет)"
			tags = []string{"live", "tcp"}
			live++
		} else if ip, ok := res.Resolved[h]; ok {
			status = "не отвечает"
			detail = "резолвится в " + ip + ", но пробы портов не ответили"
			if rn.SOCKS != "" {
				detail += " (через Tor/SOCKS — возможно ложно; перепроверь напрямую nmap)"
			} else {
				detail += " (HTTP/443/80/8443/8080/22 закрыты/фильтруются)"
			}
			tags = []string{"resolves", "no-response"}
			resolvesOnly++
		} else {
			status = "мёртвый"
			detail = "не резолвится (нет A-записи)"
			tags = []string{"dead"}
			dead++
		}
		st.Add(store.Finding{Target: h, Type: store.TypeSubdomain, Severity: store.SevInfo,
			Title: "Поддомен: " + status, Detail: detail, Tool: "recon", Tags: tags})
	}
	ev.Logf("  поддомены — живых: %d, только резолв: %d, мёртвых: %d\n", live, resolvesOnly, dead)
}

// tcpAlive пробует подключиться к 443 и 80 (с учётом Tor/SOCKS). Возвращает
// открытый порт или "". Это лёгкая «пинг»-проверка живости без внешних тулов.
func tcpAlive(ctx context.Context, rn *runner.Runner, host string) string {
	for _, port := range []string{"443", "80", "8443", "8080", "22"} {
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		var conn net.Conn
		var err error
		addr := net.JoinHostPort(host, port)
		if rn.SOCKS != "" {
			conn, err = netx.NewDialer(rn.SOCKS, 4*time.Second).DialContext(cctx, "tcp", addr)
		} else {
			conn, err = (&net.Dialer{Timeout: 4 * time.Second}).DialContext(cctx, "tcp", addr)
		}
		cancel()
		if err == nil {
			conn.Close()
			return port
		}
	}
	return ""
}

// joinPorts печатает список портов через запятую (до 8), с «…» при переполнении.
func joinPorts(ports []int) string {
	sort.Ints(ports)
	seen := map[int]bool{}
	var uniq []int
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	var parts []string
	for i, p := range uniq {
		if i >= 8 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, itoa(p))
	}
	return strings.Join(parts, ", ")
}

// hostOnly убирает порт из "host:port".
func hostOnly(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		// не трогаем IPv6 в скобках; httpx host обычно hostname[:port]
		if !strings.Contains(h, "]") {
			h = h[:i]
		}
	}
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

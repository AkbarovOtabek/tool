// Package web — веб-тестирование живых HTTP-сервисов, аналог активного и
// пассивного сканера Burp Suite, но из CLI и автоматически:
//   - пассивно: аудит security-заголовков (встроенный HTTP-клиент, без внешних тулов);
//   - директории (ffuf), параметры (arjun), XSS (dalfox);
//   - активно (по флагу): SQL-инъекции (sqlmap, щадящий режим) и DAST (nuclei -dast).
//
// Агрессивные инъекции выключены по умолчанию и включаются осознанно —
// чтобы не повредить данные клиента.
package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

// Target — вход для веб-тестирования.
type Target struct {
	URL    string
	Status int
}

// securityHeaders — заголовки, отсутствие которых считаем находкой (как пассивный скан Burp).
var securityHeaders = []struct {
	name, title string
	sev         store.Severity
}{
	{"Content-Security-Policy", "Нет Content-Security-Policy (риск XSS/инъекций контента)", store.SevLow},
	{"Strict-Transport-Security", "Нет HSTS (возможен downgrade на HTTP)", store.SevLow},
	{"X-Content-Type-Options", "Нет X-Content-Type-Options (MIME-sniffing)", store.SevInfo},
	{"X-Frame-Options", "Нет X-Frame-Options/CSP frame-ancestors (clickjacking)", store.SevInfo},
	{"Referrer-Policy", "Нет Referrer-Policy (утечка Referer)", store.SevInfo},
}

// Run прогоняет веб-проверки по целям с ограничением параллелизма.
// activeInjection включает агрессивные инъекции (sqlmap, nuclei -dast).
func Run(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, targets []Target, activeInjection bool) {
	if len(targets) == 0 {
		ev.Logln("  нет целей для веб-тестирования")
		return
	}
	client := clientFor(rn)
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		if t.Status >= 500 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			headerAudit(ctx, st, client, t.URL)              // пассивно, встроенный клиент
			corsAudit(ctx, st, client, t.URL)                // пассивно: мисконфигурация CORS
			dirScan(ctx, cfg, rn, st, ev, t.URL)             // feroxbuster/ffuf
			params := paramScan(ctx, cfg, rn, st, ev, t.URL) // arjun + dalfox
			if activeInjection {
				sqliScan(ctx, rn, st, ev, t.URL, params)
			}
		}(t)
	}
	wg.Wait()

	if activeInjection {
		nucleiDAST(ctx, rn, st, ev, targets)
	}
}

var passiveClient = &http.Client{
	Timeout: 12 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // origin/самоподписанные
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// clientFor выбирает HTTP-клиент: через SOCKS5 (Tor/прокси), если он задан.
func clientFor(rn *runner.Runner) *http.Client {
	if rn.SOCKS != "" {
		return netx.HTTPClient(rn.SOCKS, 12*time.Second, true)
	}
	return passiveClient
}

// headerAudit — пассивный аудит security-заголовков (эквивалент passive scan Burp).
func headerAudit(ctx context.Context, st *store.Store, client *http.Client, u string) {
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", netx.RandomUA())
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	for _, h := range securityHeaders {
		if resp.Header.Get(h.name) == "" {
			st.Add(store.Finding{Target: u, Type: store.TypeHeader, Severity: h.sev,
				Title: h.title, Tool: "pentkit", Tags: []string{"security-header", "passive"}})
		}
	}
	// Раскрытие версий ПО через заголовки.
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := resp.Header.Get(h); v != "" && hasVersion(v) {
			st.Add(store.Finding{Target: u, Type: store.TypeHeader, Severity: store.SevInfo,
				Title: "Раскрытие версии в заголовке " + h + ": " + v,
				Tool:  "pentkit", Tags: []string{"info-disclosure", "passive"}})
		}
	}
}

func hasVersion(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// corsAudit — пассивная проверка CORS: шлём чужой Origin и смотрим, отражает ли
// его сервер в Access-Control-Allow-Origin. Отражение + allow-credentials = дыра
// (чужой сайт сможет читать приватные ответы от имени жертвы). Один запрос, тихо.
func corsAudit(ctx context.Context, st *store.Store, client *http.Client, u string) {
	const evil = "https://pentkit-cors-probe.example"
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", evil)
	req.Header.Set("User-Agent", netx.RandomUA())
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case acao == evil && acac:
		st.Add(store.Finding{Target: u, Type: store.TypeCORS, Severity: store.SevHigh,
			Title:    "CORS: отражение Origin + allow-credentials",
			Evidence: "ACAO отразил " + evil + ", ACAC=true — чужой сайт читает приватные данные",
			Tool:     "pentkit", Tags: []string{"cors", "requires-review"}})
	case acao == evil:
		st.Add(store.Finding{Target: u, Type: store.TypeCORS, Severity: store.SevMedium,
			Title:    "CORS: отражение произвольного Origin",
			Evidence: "ACAO отразил " + evil, Tool: "pentkit", Tags: []string{"cors", "requires-review"}})
	case acao == "null":
		st.Add(store.Finding{Target: u, Type: store.TypeCORS, Severity: store.SevMedium,
			Title: "CORS: Access-Control-Allow-Origin: null", Tool: "pentkit",
			Tags: []string{"cors", "requires-review"}})
	}
}

func dirScan(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, base string) {
	// feroxbuster — рекурсивный перебор директорий: находит вложенные пути,
	// которые одноуровневый ffuf пропускает. Предпочитаем его, если установлен.
	if rn.Has("feroxbuster") {
		feroxScan(ctx, cfg, rn, st, ev, base)
		return
	}
	if !rn.Has("ffuf") {
		return
	}
	u := strings.TrimRight(base, "/") + "/FUZZ"
	ffufArgs := []string{"-u", u, "-w", cfg.Wordlists.Dirs,
		"-mc", "200,204,301,302,307,401,403", "-ac", "-s"}
	if rn.Stealthy() {
		// Дирбаст — главный триггер блок-листа WAF: мало потоков, джиттер,
		// лимит rate и случайный User-Agent, чтобы не ловить бан по частоте 404.
		ffufArgs = append(ffufArgs, "-t", "5", "-p", "0.1-0.4", "-H", "User-Agent: "+netx.RandomUA())
		if cfg.RateLimit > 0 {
			ffufArgs = append(ffufArgs, "-rate", strconv.Itoa(cfg.RateLimit))
		}
	} else {
		ffufArgs = append(ffufArgs, "-t", "40")
	}
	r := rn.Run(ctx, "ffuf", ffufArgs...)
	n := 0
	for _, path := range r.Lines {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		full := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
		if st.Add(store.Finding{Target: full, Type: store.TypeDir, Severity: store.SevLow,
			Title: "Найден путь: /" + strings.TrimLeft(path, "/"), Tool: "ffuf"}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  ffuf %s: путей %d\n", base, n)
	}
}

// feroxScan — рекурсивный перебор директорий feroxbuster.
func feroxScan(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, base string) {
	args := []string{"-u", base, "-w", cfg.Wordlists.Dirs, "--silent", "-k", "-d", "2",
		"-C", "404", "-E"} // -E: собирать ссылки/расширения; -C 404: отсев
	if rn.Stealthy() {
		args = append(args, "-t", "4", "--auto-tune")
		if cfg.RateLimit > 0 {
			args = append(args, "--rate-limit", strconv.Itoa(cfg.RateLimit))
		}
	} else {
		args = append(args, "-t", "40")
	}
	r := rn.Run(ctx, "feroxbuster", args...)
	n := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "http") {
			continue
		}
		if st.Add(store.Finding{Target: line, Type: store.TypeDir, Severity: store.SevLow,
			Title: "Найден путь: " + line, Tool: "feroxbuster"}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  feroxbuster %s: путей %d\n", base, n)
	}
}

// DalfoxPipe прогоняет пачку URL-кандидатов на XSS (из gf xss) через dalfox pipe —
// это бьёт по всем параметризованным URL сразу, а не по одному, как paramScan.
func DalfoxPipe(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, xssURLs []string) {
	if !rn.Has("dalfox") || len(xssURLs) == 0 {
		return
	}
	if len(xssURLs) > 300 {
		xssURLs = xssURLs[:300]
	}
	ev.Logf("  dalfox pipe: проверяю %d XSS-кандидатов...\n", len(xssURLs))
	args := []string{"pipe", "--silence", "--no-color", "--format", "plain"}
	if rn.Stealthy() {
		args = append(args, "--delay", "500", "--worker", "5")
	}
	r := rn.RunStdin(ctx, strings.Join(xssURLs, "\n"), "dalfox", args...)
	n := 0
	for _, line := range r.Lines {
		if strings.Contains(strings.ToUpper(line), "POC") || strings.Contains(line, "[V]") {
			if st.Add(store.Finding{Target: dalfoxURL(line), Type: store.TypeInjection, Severity: store.SevHigh,
				Title: "Возможный XSS (dalfox pipe)", Evidence: trimLine(line, 300),
				Tool: "dalfox", Tags: []string{"xss", "requires-review"}}) {
				n++
			}
		}
	}
	if n > 0 {
		ev.Logf("  dalfox pipe: находок %d\n", n)
	}
}

// DASTOnURLs гоняет nuclei -dast по параметризованным URL-кандидатам (gf),
// а не по одним главным страницам — так fuzzing попадает в реальные точки входа.
func DASTOnURLs(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("nuclei") || len(urls) == 0 {
		return
	}
	if len(urls) > 500 {
		urls = urls[:500]
	}
	ev.Logf("  nuclei -dast: fuzzing %d URL-кандидатов...\n", len(urls))
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "nuclei", "-dast", "-silent", "-nc", "-jsonl")
	n := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if st.Add(store.Finding{Target: firstURL(line), Type: store.TypeInjection, Severity: store.SevHigh,
			Title: "DAST-находка (nuclei fuzzing)", Evidence: trimLine(line, 300),
			Tool: "nuclei", Tags: []string{"dast", "requires-review"}}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  nuclei -dast: находок %d\n", n)
	}
}

func dalfoxURL(line string) string {
	if i := strings.Index(line, "http"); i >= 0 {
		rest := line[i:]
		if j := strings.IndexAny(rest, " \t"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return "dalfox"
}

// paramScan находит скрытые параметры (arjun) и проверяет XSS (dalfox).
// Возвращает найденные имена параметров для последующих инъекций.
func paramScan(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, base string) []string {
	if !rn.Has("arjun") {
		return nil
	}
	arjunArgs := []string{"-u", base, "-q", "-oT", "/dev/stdout"}
	if rn.Stealthy() {
		arjunArgs = append(arjunArgs, "-d", "2", "--stable") // задержка между запросами
	}
	r := rn.Run(ctx, "arjun", arjunArgs...)
	var params []string
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "?"); i >= 0 {
			params = append(params, line[i+1:])
		}
	}
	if len(params) == 0 {
		return nil
	}
	st.Add(store.Finding{Target: base, Type: store.TypeParam, Severity: store.SevInfo,
		Title:  "Найдено параметров: " + strconv.Itoa(len(params)),
		Detail: strings.Join(params, " "), Tool: "arjun"})

	if rn.Has("dalfox") {
		testURL := base + "?" + params[0]
		dalfoxArgs := []string{"url", testURL, "--silence", "--no-color", "--format", "plain"}
		if rn.Stealthy() {
			dalfoxArgs = append(dalfoxArgs, "--delay", "500", "--worker", "5") // мс между запросами
		}
		dr := rn.Run(ctx, "dalfox", dalfoxArgs...)
		for _, line := range dr.Lines {
			if strings.Contains(strings.ToUpper(line), "POC") || strings.Contains(line, "[V]") {
				st.Add(store.Finding{Target: testURL, Type: store.TypeInjection, Severity: store.SevHigh,
					Title: "Возможный XSS", Evidence: line, Tool: "dalfox", Tags: []string{"xss", "requires-review"}})
				ev.Logf("  dalfox: возможный XSS на %s\n", testURL)
			}
		}
	}
	return params
}

// sqliScan — активная проверка SQL-инъекций sqlmap в ЩАДЯЩЕМ режиме
// (--level 1 --risk 1, без --dump/--os-shell). Включается только по флагу.
func sqliScan(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, base string, params []string) {
	if !rn.Has("sqlmap") || len(params) == 0 {
		return
	}
	testURL := base + "?" + params[0]
	ev.Logf("  sqlmap: проверяю %s (щадящий режим)...\n", testURL)
	sqlArgs := []string{"-u", testURL, "--batch", "--level", "1", "--risk", "1",
		"--technique", "BEUST", "--smart", "--threads", "2", "--disable-coloring"}
	if rn.Stealthy() {
		// Случайный UA + задержка — чтобы инъекционные пробы не словили блок.
		sqlArgs = append(sqlArgs, "--random-agent", "--delay", "1")
	}
	r := rn.Run(ctx, "sqlmap", sqlArgs...)
	out := r.Stdout + "\n" + r.Stderr
	low := strings.ToLower(out)
	if strings.Contains(low, "is vulnerable") || strings.Contains(low, "injectable") ||
		strings.Contains(low, "parameter:") && strings.Contains(low, "type:") {
		st.Add(store.Finding{Target: testURL, Type: store.TypeInjection, Severity: store.SevCritical,
			Title:    "Возможная SQL-инъекция (sqlmap)",
			Evidence: "sqlmap отметил параметр как инъектируемый; подтверди вручную перед эксплуатацией",
			Tool:     "sqlmap", Tags: []string{"sqli", "verified", "requires-review"}})
		ev.Logf("  sqlmap: ВОЗМОЖНАЯ SQLi на %s\n", testURL)
	}
}

// nucleiDAST — активный DAST-скан (fuzzing) nuclei по живым URL.
func nucleiDAST(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, targets []Target) {
	if !rn.Has("nuclei") {
		return
	}
	var urls []string
	for _, t := range targets {
		if t.Status < 500 {
			urls = append(urls, t.URL)
		}
	}
	if len(urls) == 0 {
		return
	}
	ev.Logln("  nuclei -dast: активный fuzzing параметров...")
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "nuclei", "-dast", "-silent", "-nc", "-jsonl")
	n := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if st.Add(store.Finding{Target: firstURL(line), Type: store.TypeInjection, Severity: store.SevHigh,
			Title: "DAST-находка (nuclei fuzzing)", Evidence: trimLine(line, 300),
			Tool: "nuclei", Tags: []string{"dast", "requires-review"}}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  nuclei -dast: находок %d\n", n)
	}
}

func firstURL(jsonLine string) string {
	for _, key := range []string{`"matched-at":"`, `"host":"`} {
		if i := strings.Index(jsonLine, key); i >= 0 {
			rest := jsonLine[i+len(key):]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				return rest[:j]
			}
		}
	}
	return "dast"
}

func trimLine(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// CRLFuzz проверяет параметризованные URL на CRLF-инъекции (внешний crlfuzz).
func CRLFuzz(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("crlfuzz") {
		if len(urls) > 0 {
			ev.Logln("  ! crlfuzz не установлен — пропускаю CRLF (go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest)")
		}
		return
	}
	if len(urls) == 0 {
		return
	}
	if len(urls) > 300 {
		urls = urls[:300]
	}
	args := []string{"-s", "-c", "15"}
	if rn.Stealthy() {
		args = []string{"-s", "-c", "5", "-d", "200"}
	}
	ev.Logf("  crlfuzz: проверяю %d URL на CRLF-инъекции...\n", len(urls))
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "crlfuzz", args...)
	n := 0
	for _, line := range r.Lines {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "http") {
			continue
		}
		if st.Add(store.Finding{Target: l, Type: store.TypeInjection, Severity: store.SevMedium,
			Title: "Возможная CRLF-инъекция", Evidence: trimLine(l, 300),
			Tool: "crlfuzz", Tags: []string{"crlf", "requires-review"}}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  crlfuzz: находок %d\n", n)
	}
}

// X8 фаззит скрытые параметры (внешний x8). Нужен словарь имён параметров
// (cfg.Wordlists.Params); без него пропускаем. Активная проверка.
func X8(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("x8") {
		return
	}
	wl := cfg.Wordlists.Params
	if wl == "" {
		ev.Logln("  ! x8: не задан словарь параметров (config.wordlists.params) — пропускаю")
		return
	}
	if len(urls) > 15 {
		urls = urls[:15]
	}
	for _, u := range urls {
		r := rn.Run(ctx, "x8", "-u", u, "-w", wl, "-O", "json")
		for _, line := range r.Lines {
			l := strings.TrimSpace(line)
			if strings.Contains(l, "found") || strings.Contains(strings.ToLower(l), "param") {
				st.Add(store.Finding{Target: u, Type: store.TypeParam, Severity: store.SevInfo,
					Title: "x8: скрытый параметр", Evidence: trimLine(l, 200),
					Tool: "x8", Tags: []string{"param", "hidden"}})
			}
		}
	}
}

// Ghauri — альтернативный движок SQL-инъекций (быстрее sqlmap на части кейсов).
// Активная проверка: вызывается только в SQLi-режиме.
func Ghauri(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("ghauri") {
		return
	}
	if len(urls) > 10 {
		urls = urls[:10]
	}
	ev.Logf("  ghauri: проверяю %d URL на SQLi...\n", len(urls))
	for _, u := range urls {
		r := rn.Run(ctx, "ghauri", "-u", u, "--batch", "--level", "1")
		for _, line := range r.Lines {
			low := strings.ToLower(line)
			if strings.Contains(low, "injectable") || strings.Contains(low, "parameter") && strings.Contains(low, "vulnerable") {
				st.Add(store.Finding{Target: u, Type: store.TypeInjection, Severity: store.SevHigh,
					Title: "SQL-инъекция (ghauri)", Evidence: trimLine(strings.TrimSpace(line), 300),
					Tool: "ghauri", Tags: []string{"sqli", "requires-review"}})
			}
		}
	}
}

// Gxss ищет параметры, значение которых отражается в ответе (кандидаты на XSS).
// Дополняет dalfox: сначала сужаем до реально отражающихся точек.
func Gxss(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("Gxss") || len(urls) == 0 {
		return
	}
	if len(urls) > 500 {
		urls = urls[:500]
	}
	args := []string{"-c", "30"}
	if rn.Stealthy() {
		args = []string{"-c", "5"}
	}
	ev.Logf("  Gxss: проверяю отражение в %d URL...\n", len(urls))
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "Gxss", args...)
	n := 0
	for _, line := range r.Lines {
		l := strings.TrimSpace(line)
		if !strings.Contains(l, "http") {
			continue
		}
		// Gxss печатает "URL ... Vulnerable" / "reflection found" — берём URL.
		u := l
		if i := strings.Index(l, "http"); i > 0 {
			u = l[i:]
		}
		if sp := strings.IndexByte(u, ' '); sp > 0 {
			u = u[:sp]
		}
		if st.Add(store.Finding{Target: u, Type: store.TypeParam, Severity: store.SevLow,
			Title: "Отражение параметра (кандидат на XSS)", Evidence: trimLine(l, 200),
			Tool: "Gxss", Tags: []string{"xss", "reflection", "requires-review"}}) {
			n++
		}
	}
	if n > 0 {
		ev.Logf("  Gxss: отражающихся точек %d\n", n)
	}
}

// Oralyzer проверяет открытые редиректы по URL-кандидатам (gf redirect).
func Oralyzer(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("oralyzer") || len(urls) == 0 {
		return
	}
	if len(urls) > 60 {
		urls = urls[:60]
	}
	ev.Logf("  oralyzer: проверяю %d URL на open redirect...\n", len(urls))
	for _, u := range urls {
		r := rn.Run(ctx, "oralyzer", "-u", u)
		for _, line := range r.Lines {
			low := strings.ToLower(line)
			if strings.Contains(low, "vulnerable") || strings.Contains(low, "redirect") && strings.Contains(low, "found") {
				st.Add(store.Finding{Target: u, Type: store.TypeInjection, Severity: store.SevMedium,
					Title: "Открытый редирект (open redirect)", Evidence: trimLine(strings.TrimSpace(line), 250),
					Tool: "oralyzer", Tags: []string{"open-redirect", "requires-review"}})
			}
		}
	}
}

// Commix проверяет command injection по URL-кандидатам (gf rce). Активно и
// интрузивно — вызывается только в SQLi/агрессивном режиме.
func Commix(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("commix") || len(urls) == 0 {
		return
	}
	if len(urls) > 10 {
		urls = urls[:10]
	}
	ev.Logf("  commix: проверяю %d URL на command injection...\n", len(urls))
	for _, u := range urls {
		r := rn.Run(ctx, "commix", "--url", u, "--batch", "--level", "1")
		for _, line := range r.Lines {
			low := strings.ToLower(line)
			if strings.Contains(low, "injectable") || strings.Contains(low, "vulnerable to") {
				st.Add(store.Finding{Target: u, Type: store.TypeInjection, Severity: store.SevHigh,
					Title: "Command injection (commix)", Evidence: trimLine(strings.TrimSpace(line), 300),
					Tool: "commix", Tags: []string{"command-injection", "requires-review"}})
				break
			}
		}
	}
}

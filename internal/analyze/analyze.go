// Package analyze — дополнительные инструменты анализа организации:
//   - отпечаток технологий/CMS (whatweb) и определение WAF (wafw00f);
//   - WordPress-аудит (wpscan);
//   - OSINT: почты и хосты из открытых источников (theHarvester);
//   - расширение поверхности: пассивные поддомены (amass, assetfinder).
//
// Все тулы необязательны: отсутствующий в PATH тул пропускается с предупреждением.
package analyze

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/store"
)

// defaultResolvers — публичные DNS-резолверы для puredns, если своих нет.
const defaultResolvers = "1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n208.67.222.222\n"

// BruteSubdomains — активный перебор поддоменов по словарю (puredns + massdns).
// puredns валидирует каждый кандидат через резолверы, поэтому возвращает только
// реально резолвящиеся хосты. Нужны puredns, massdns и словарь (cfg.Wordlists.Subs).
func BruteSubdomains(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink, engDir string, domains []string) []string {
	if rn.Passive {
		ev.Logln("  пассивный режим: брут поддоменов (puredns) пропущен")
		return nil
	}
	if !rn.Has("puredns") || !rn.Has("massdns") {
		ev.Logln("  ! puredns/massdns не установлены — пропускаю брут поддоменов")
		return nil
	}
	wl := cfg.Wordlists.Subs
	if wl == "" {
		ev.Logln("  ! не задан словарь поддоменов (config.wordlists.subs) — пропускаю брут")
		return nil
	}
	resolvers := filepath.Join(engDir, "resolvers.txt")
	if _, err := os.Stat(resolvers); err != nil {
		_ = os.WriteFile(resolvers, []byte(defaultResolvers), 0o640)
	}
	set := map[string]bool{}
	for _, d := range domains {
		ev.Logf("  puredns: брут поддоменов %s по словарю...\n", d)
		r := rn.Run(ctx, "puredns", "bruteforce", wl, d, "-r", resolvers, "-q", "--skip-wildcard-filter")
		for _, h := range r.Lines {
			add(set, sc, h)
		}
	}

	// dnsgen: перестановки из найденного → ещё один проход резолва puredns.
	if rn.Has("dnsgen") && len(set) > 0 {
		seed := make([]string, 0, len(set))
		for h := range set {
			seed = append(seed, h)
		}
		dg := rn.RunStdin(ctx, strings.Join(seed, "\n"), "dnsgen", "-")
		if len(dg.Lines) > 0 {
			ev.Logf("  dnsgen: перестановок %d — резолвлю...\n", len(dg.Lines))
			pr := rn.RunStdin(ctx, strings.Join(dg.Lines, "\n"), "puredns", "resolve", "-r", resolvers, "-q", "--skip-wildcard-filter")
			for _, h := range pr.Lines {
				add(set, sc, h)
			}
		}
	}

	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
		st.Add(store.Finding{Target: h, Type: store.TypeSubdomain, Severity: store.SevInfo,
			Title: "Поддомен: жив (брут)", Detail: "найден брутом/перестановкой и резолвится",
			Tool: "puredns", Tags: []string{"live", "brute", "resolves"}})
	}
	if len(out) > 0 {
		ev.Logf("  puredns: доп. резолвящихся поддоменов: %d\n", len(out))
	}
	return out
}

const (
	maxFingerprint = 40
	maxWPScan      = 10
)

var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// ExtraSubdomains добавляет поддомены из пассивных источников (amass,
// assetfinder, findomain). Источники по каждому домену запускаются параллельно —
// они независимы, последовательное ожидание только тормозит разведку.
// Возвращает хосты в скоупе для вливания в общий пайплайн recon.
func ExtraSubdomains(ctx context.Context, rn *runner.Runner, sc *scope.Scope, ev event.Sink, domains []string) []string {
	set := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	run := func(tool string, args ...string) {
		defer wg.Done()
		r := rn.Run(ctx, tool, args...)
		mu.Lock()
		for _, h := range r.Lines {
			add(set, sc, h)
		}
		mu.Unlock()
	}
	for _, d := range domains {
		if rn.Has("amass") {
			wg.Add(1)
			go run("amass", "enum", "-passive", "-silent", "-d", d)
		}
		if rn.Has("assetfinder") {
			wg.Add(1)
			go run("assetfinder", "--subs-only", d)
		}
		if rn.Has("findomain") {
			// findomain — быстрый пассивный сборщик из десятков источников.
			wg.Add(1)
			go run("findomain", "-t", d, "-q")
		}
		if rn.Has("tlsx") {
			// tlsx — поддомены из SAN TLS-сертификата (ещё один пассивный источник).
			wg.Add(1)
			go run("tlsx", "-u", d, "-san", "-silent", "-resp-only")
		}
	}
	wg.Wait()
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	if len(out) > 0 {
		ev.Logf("  amass/assetfinder/findomain: доп. поддоменов в скоупе: %d\n", len(out))
	}
	return out
}

func add(set map[string]bool, sc *scope.Scope, h string) {
	h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "*.")))
	if h != "" && sc.InScope(h) {
		set[h] = true
	}
}

// Uncover ищет хосты через Shodan по домену (uncover). Нужен ключ Shodan.
// Запросы идут к Shodan, а не к цели — пассивное расширение поверхности.
func Uncover(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink, domains []string) []string {
	if !rn.Has("uncover") || cfg.Keys.Shodan == "" {
		return nil
	}
	os.Setenv("SHODAN_API_KEY", cfg.Keys.Shodan)
	set := map[string]bool{}
	for _, d := range domains {
		r := rn.Run(ctx, "uncover", "-shodan", "ssl:\""+d+"\"", "-silent")
		for _, line := range r.Lines {
			h := strings.TrimSpace(line)
			if i := strings.LastIndexByte(h, ':'); i >= 0 { // host:port -> host
				h = h[:i]
			}
			add(set, sc, h)
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	if len(out) > 0 {
		ev.Logf("  uncover (Shodan): доп. хостов в скоупе: %d\n", len(out))
	}
	return out
}

// Fingerprint снимает отпечаток технологий (whatweb) и определяет WAF (wafw00f).
func Fingerprint(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	haveWW := rn.Has("whatweb")
	// wafw00f шлёт заведомо вредоносные пробы для детекта WAF — в пассивном
	// режиме это ровно то, что нельзя: пропускаем, оставляя только whatweb.
	haveWaf := rn.Has("wafw00f") && !rn.Passive
	if rn.Passive && rn.Has("wafw00f") {
		ev.Logln("  пассивный режим: wafw00f пропущен (активные пробы WAF)")
	}
	if !haveWW && !haveWaf {
		ev.Logln("  ! whatweb/wafw00f не установлены — пропускаю отпечаток (apt install whatweb wafw00f)")
		return
	}
	urls = capN(urls, maxFingerprint)
	for _, u := range urls {
		if haveWW {
			r := rn.Run(ctx, "whatweb", "--no-errors", "--color=never", "-a", "1", u)
			if line := strings.TrimSpace(r.Stdout); line != "" {
				st.Add(store.Finding{Target: u, Type: store.TypeTech, Severity: store.SevInfo,
					Title: "Отпечаток технологий", Detail: firstLine(line), Tool: "whatweb"})
			}
		}
		if haveWaf {
			r := rn.Run(ctx, "wafw00f", "-a", u)
			for _, line := range r.Lines {
				if strings.Contains(strings.ToLower(line), "is behind") {
					st.Add(store.Finding{Target: u, Type: store.TypeWAF, Severity: store.SevInfo,
						Title: "Обнаружен WAF", Detail: strings.TrimSpace(line),
						Evidence: "учитывай WAF при тестировании (возможны ложные блокировки/обходы)",
						Tool:     "wafw00f", Tags: []string{"waf"}})
					ev.Logf("  wafw00f %s: %s\n", u, strings.TrimSpace(line))
				}
			}
		}
	}
}

// WordPress запускает wpscan по URL, где обнаружен WordPress.
func WordPress(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, wpURLs []string) {
	if !rn.Has("wpscan") {
		if len(wpURLs) > 0 {
			ev.Logln("  ! wpscan не установлен — пропускаю WordPress-аудит (apt install wpscan)")
		}
		return
	}
	wpURLs = capN(wpURLs, maxWPScan)
	for _, u := range wpURLs {
		ev.Logf("  wpscan: %s ...\n", u)
		r := rn.Run(ctx, "wpscan", "--url", u, "--no-banner", "--random-user-agent",
			"--format", "cli-no-color", "--disable-tls-checks")
		n := 0
		for _, line := range r.Lines {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "[!]") || strings.Contains(strings.ToLower(l), "vulnerab") {
				sev := store.SevMedium
				if strings.Contains(strings.ToLower(l), "critical") {
					sev = store.SevHigh
				}
				st.Add(store.Finding{Target: u, Type: store.TypeVuln, Severity: sev,
					Title: "WordPress: " + trim(strings.TrimPrefix(l, "[!]"), 120),
					Tool:  "wpscan", Tags: []string{"wordpress", "requires-review"}})
				n++
			}
		}
		if n > 0 {
			ev.Logf("  wpscan %s: заметок %d\n", u, n)
		}
	}
}

// OSINT собирает почты и хосты из открытых источников (theHarvester).
func OSINT(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, domains []string) {
	if !rn.Has("theHarvester") && !rn.Has("theharvester") {
		ev.Logln("  ! theHarvester не установлен — пропускаю OSINT (pipx install theHarvester)")
		return
	}
	bin := "theHarvester"
	if !rn.Has("theHarvester") {
		bin = "theharvester"
	}
	for _, d := range domains {
		r := rn.Run(ctx, bin, "-d", d, "-b", "crtsh,duckduckgo,bing,otx", "-l", "200")
		emails := map[string]bool{}
		for _, m := range emailRe.FindAllString(r.Stdout, -1) {
			emails[strings.ToLower(m)] = true
		}
		if len(emails) == 0 {
			continue
		}
		var list []string
		for e := range emails {
			list = append(list, e)
		}
		st.Add(store.Finding{Target: d, Type: store.TypeOSINT, Severity: store.SevInfo,
			Title:    "Найдено почт: " + strconv.Itoa(len(list)),
			Detail:   strings.Join(list, ", "),
			Evidence: "потенциальные цели для фишинга/перебора — учти в отчёте",
			Tool:     "theHarvester", Tags: []string{"osint", "emails"}})
		ev.Logf("  theHarvester %s: почт %d\n", d, len(list))
	}
}

// --- утилиты ---

func capN(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return trim(strings.TrimSpace(s), 300)
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

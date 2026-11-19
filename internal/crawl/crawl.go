// Package crawl расширяет поверхность атаки: краулинг (katana) и сбор URL из
// веб-архивов (gau). Собранные URL отдаются дальше в nuclei и веб-тесты.
package crawl

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/store"
)

// Run краулит seed-URL и собирает архивные URL для доменов скоупа.
// Возвращает дедуплицированный список URL в скоупе.
func Run(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink, seeds []string) []string {
	set := map[string]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		if sc.InScope(u.Hostname()) {
			set[raw] = true
		}
	}

	// 1. katana — активный краулинг живых сервисов.
	if rn.Has("katana") && len(seeds) > 0 {
		katanaArgs := []string{"-silent", "-jc", "-d", "2", "-fs", "fqdn"}
		if cfg.RateLimit > 0 {
			katanaArgs = append(katanaArgs, "-rl", itoa(cfg.RateLimit))
		}
		r := rn.RunStdin(ctx, strings.Join(seeds, "\n"), "katana", katanaArgs...)
		for _, line := range r.Lines {
			add(line)
		}
		ev.Logf("  katana: собрано URL %d\n", len(set))
	} else if !rn.Has("katana") {
		ev.Logln("  ! katana не установлен — пропускаю краулинг")
	}

	// 2. gau — URL из веб-архивов (Wayback, CommonCrawl) по доменам скоупа.
	if rn.Has("gau") {
		before := len(set)
		r := rn.RunStdin(ctx, strings.Join(sc.Domains(), "\n"), "gau", "--subs", "--threads", "5")
		for _, line := range r.Lines {
			add(line)
		}
		ev.Logf("  gau: добавлено URL %d\n", len(set)-before)
	} else {
		ev.Logln("  ! gau не установлен — пропускаю архивные URL")
	}

	// 3. waybackurls — ещё один источник архивных URL (дополняет gau: разные
	//    индексы дают разные исторические пути/параметры = шире поверхность).
	if rn.Has("waybackurls") {
		before := len(set)
		r := rn.RunStdin(ctx, strings.Join(sc.Domains(), "\n"), "waybackurls")
		for _, line := range r.Lines {
			add(line)
		}
		ev.Logf("  waybackurls: добавлено URL %d\n", len(set)-before)
	}

	// 4. paramspider — URL с параметрами из архивов (прицельно на точки инъекций).
	if rn.Has("paramspider") {
		before := len(set)
		for _, d := range sc.Domains() {
			r := rn.Run(ctx, "paramspider", "-d", d, "--subs", "-o", "/dev/stdout")
			for _, line := range r.Lines {
				if strings.HasPrefix(strings.TrimSpace(line), "http") {
					add(line)
				}
			}
		}
		if n := len(set) - before; n > 0 {
			ev.Logf("  paramspider: добавлено URL %d\n", n)
		}
	}

	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	if len(out) > 0 {
		st.Add(store.Finding{Target: strings.Join(sc.Domains(), ","), Type: store.TypeParam,
			Severity: store.SevInfo, Title: "Собрано URL (краулинг/архивы): " + itoa(len(out)),
			Tool: "katana/gau"})
	}
	return out
}

// Candidates — URL, рассортированные по типу потенциальной уязвимости (через gf),
// плюс отдельно собранные .js для поиска утечек секретов.
type Candidates struct {
	XSS      []string
	SQLi     []string
	SSRF     []string
	LFI      []string
	Redirect []string
	RCE      []string
	JS       []string
}

// Triage прогоняет собранные URL через gf-паттерны и выделяет точки инъекций.
// Это классический white-hat workflow: вместо слепого фаззинга всех URL мы
// сразу получаем параметризованные кандидаты под XSS/SQLi/SSRF/LFI/redirect,
// что радикально ускоряет поиск реальных дыр. .js-файлы собираем для secrets.
func Triage(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) Candidates {
	var c Candidates
	// .js — просто по расширению, gf не нужен.
	for _, u := range urls {
		if isJS(u) {
			c.JS = append(c.JS, u)
		}
	}
	if len(c.JS) > 0 {
		ev.Logf("  найдено JS-файлов для анализа секретов: %d\n", len(c.JS))
	}

	if !rn.Has("gf") || len(urls) == 0 {
		if !rn.Has("gf") && len(urls) > 0 {
			ev.Logln("  ! gf не установлен — пропускаю сортировку URL по типам инъекций (go install .../gf@latest + gf-patterns)")
		}
		return c
	}
	blob := strings.Join(urls, "\n")
	cats := []struct {
		pattern string
		label   string
		dst     *[]string
	}{
		{"xss", "XSS", &c.XSS},
		{"sqli", "SQLi", &c.SQLi},
		{"ssrf", "SSRF", &c.SSRF},
		{"lfi", "LFI/path-traversal", &c.LFI},
		{"redirect", "open-redirect", &c.Redirect},
		{"rce", "RCE", &c.RCE},
	}
	for _, cat := range cats {
		r := rn.RunStdin(ctx, blob, "gf", cat.pattern)
		seen := map[string]bool{}
		for _, line := range r.Lines {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			*cat.dst = append(*cat.dst, line)
		}
		if len(*cat.dst) > 0 {
			ev.Logf("  gf %s: кандидатов %d\n", cat.pattern, len(*cat.dst))
			st.Add(store.Finding{Target: "scope", Type: store.TypeParam, Severity: store.SevInfo,
				Title:  "Кандидаты на " + cat.label + ": " + itoa(len(*cat.dst)),
				Detail: sample(*cat.dst, 5), Tool: "gf",
				Tags: []string{"attack-surface", cat.pattern}})
		}
	}
	return c
}

func isJS(u string) bool {
	q := u
	if i := strings.IndexByte(q, '?'); i >= 0 {
		q = q[:i]
	}
	return strings.HasSuffix(strings.ToLower(q), ".js")
}

func sample(in []string, n int) string {
	if len(in) > n {
		return strings.Join(in[:n], "  ") + " …"
	}
	return strings.Join(in, "  ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

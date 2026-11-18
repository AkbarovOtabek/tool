// Package engine — единый оркестратор пайплайна. Используется и CLI, и веб-UI.
// Разведка выполняется всегда (основа для остальных этапов); прочие модули
// включаются через Options.
package engine

import (
	"context"
	"sort"
	"strings"

	"pentkit/internal/analyze"
	"pentkit/internal/cloudflare"
	"pentkit/internal/config"
	"pentkit/internal/crawl"
	"pentkit/internal/event"
	"pentkit/internal/exploit"
	"pentkit/internal/extra"
	"pentkit/internal/recon"
	"pentkit/internal/report"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/secrets"
	"pentkit/internal/store"
	"pentkit/internal/vuln"
	"pentkit/internal/web"
)

// Options включает/выключает модули сканирования.
type Options struct {
	Cloudflare  bool // поиск и подтверждение origin за Cloudflare
	Crawl       bool // katana + gau
	Fingerprint bool // whatweb + wafw00f (технологии/CMS/WAF)
	OSINT       bool // theHarvester (почты/хосты)
	Vuln        bool // nuclei
	Secrets     bool // поиск утечек ключей/токенов в JS
	Web         bool // ffuf/arjun/dalfox + аудит заголовков
	SQLi        bool // активные инъекции: sqlmap + nuclei -dast (агрессивно)
	WordPress   bool // wpscan
	TLS         bool // testssl
	Nikto       bool // nikto
	Takeover    bool // subdomain takeover
	Screenshots bool // gowitness
	Nmap        bool // nmap -sV + NSE vuln
	Exploit     bool // searchsploit + Metasploit .rc (без автозапуска)
	MsfCheck    bool // Metasploit check (неинтрузивное подтверждение)
	Verify      bool // перепроверка срабатываний nuclei
}

// AllOn возвращает профиль «всё включено» (кроме агрессивных SQL-инъекций —
// их включают осознанно, чтобы не повредить данные клиента).
func AllOn() Options {
	return Options{
		Cloudflare: true, Crawl: true, Fingerprint: true, OSINT: true,
		Vuln: true, Secrets: true, Web: true, WordPress: true,
		TLS: true, Nikto: true, Takeover: true, Screenshots: true,
		Nmap: true, Exploit: true, MsfCheck: true, Verify: true,
	}
}

const (
	maxTLSHosts = 10
	maxNiktoURL = 10
)

// Run выполняет пайплайн и генерирует отчёт. Возвращает путь к HTML-отчёту.
func Run(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink, opts Options) (string, error) {
	ev.Stage("Разведка")
	rec, err := recon.Run(ctx, cfg, sc, rn, st, ev)
	if err != nil {
		return "", err
	}

	urls := rec.URLs()
	hosts := hostnames(rec)

	if opts.Crawl {
		ev.Stage("Краулинг и веб-архивы")
		extraURLs := crawl.Run(ctx, cfg, sc, rn, st, ev, urls)
		urls = mergeURLs(urls, extraURLs)
	}

	// Сортировка URL по типам инъекций (gf) + сбор JS. Делаем один раз — дальше
	// кандидаты переиспользуют и secrets, и web-тесты, и DAST.
	var cand crawl.Candidates
	if opts.Secrets || opts.Web || opts.SQLi {
		cand = crawl.Triage(ctx, rn, st, ev, urls)
	}

	if opts.Secrets {
		ev.Stage("Утечки секретов в JS")
		secrets.Run(ctx, rn, st, ev, cand.JS)
	}

	if opts.Fingerprint {
		ev.Stage("Отпечаток (whatweb/wafw00f)")
		analyze.Fingerprint(ctx, rn, st, ev, rec.URLs())
	}

	if opts.OSINT {
		ev.Stage("OSINT (theHarvester)")
		analyze.OSINT(ctx, rn, st, ev, sc.Domains())
	}

	if opts.Cloudflare {
		ev.Stage("Cloudflare / поиск origin")
		cloudflare.Run(ctx, cfg, sc, rn, st, ev, rec.Subdomains)
	}

	if opts.WordPress {
		ev.Stage("WordPress (wpscan)")
		analyze.WordPress(ctx, rn, st, ev, wordpressURLs(rec))
	}

	if opts.Takeover {
		ev.Stage("Subdomain takeover")
		extra.Takeover(ctx, rn, st, ev, rec.Subdomains)
	}

	if opts.Vuln {
		ev.Stage("Уязвимости (nuclei)")
		vuln.Run(ctx, cfg, rn, st, ev, urls, opts.Verify)
	}

	var nmapXML string
	var products, cves []string
	if opts.Nmap {
		ev.Stage("nmap (версии сервисов + NSE vuln)")
		tgt := hosts
		if len(tgt) == 0 {
			tgt = sc.Domains()
		}
		nmapXML, products, cves = exploit.Nmap(ctx, cfg, rn, st, ev, tgt)
	}

	if opts.Exploit {
		ev.Stage("Эксплойты (searchsploit + Metasploit .rc)")
		terms := append(products, exploit.ProductsFromStore(st)...)
		exploit.Searchsploit(ctx, rn, st, ev, terms)
		exploit.MetasploitScript(st, ev, cfg.Engagement.Name, nmapXML, cves)
	}

	if opts.MsfCheck {
		ev.Stage("Metasploit check (неинтрузивное подтверждение)")
		tgt := hosts
		if len(tgt) == 0 {
			tgt = sc.Domains()
		}
		exploit.MsfCheck(ctx, rn, st, ev, tgt, cves)
	}

	if opts.TLS {
		ev.Stage("TLS (testssl)")
		extra.TLS(ctx, rn, st, ev, hosts, maxTLSHosts)
	}

	if opts.Nikto {
		ev.Stage("Веб-сервер (nikto)")
		extra.Nikto(ctx, rn, st, ev, rec.URLs(), maxNiktoURL)
	}

	if opts.Web {
		ev.Stage("Веб-тестирование")
		web.Run(ctx, cfg, rn, st, ev, webTargets(rec), opts.SQLi)
		// Прицельный XSS по всем параметризованным URL-кандидатам (gf xss).
		web.DalfoxPipe(ctx, rn, st, ev, cand.XSS)
		if opts.SQLi {
			// Активный DAST-фаззинг по реальным точкам входа, а не по главным страницам.
			web.DASTOnURLs(ctx, rn, st, ev, injectionURLs(cand))
		}
	}

	if opts.Screenshots {
		ev.Stage("Скриншоты")
		extra.Screenshots(ctx, cfg, rn, st, ev, rec.URLs())
	}

	ev.Stage("Отчёт")
	return report.Generate(cfg, st)
}

func hostnames(rec *recon.Result) []string {
	set := map[string]bool{}
	for _, s := range rec.HTTP {
		if s.Host != "" {
			set[s.Host] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// wordpressURLs выбирает URL, где httpx определил WordPress.
func wordpressURLs(rec *recon.Result) []string {
	var out []string
	for _, s := range rec.HTTP {
		for _, t := range s.Tech {
			if strings.Contains(strings.ToLower(t), "wordpress") {
				out = append(out, s.URL)
				break
			}
		}
	}
	return out
}

func webTargets(rec *recon.Result) []web.Target {
	var t []web.Target
	for _, s := range rec.HTTP {
		t = append(t, web.Target{URL: s.URL, Status: s.Status})
	}
	return t
}

// injectionURLs объединяет все параметризованные кандидаты (gf) для DAST-фаззинга.
func injectionURLs(c crawl.Candidates) []string {
	set := map[string]bool{}
	for _, g := range [][]string{c.XSS, c.SQLi, c.SSRF, c.LFI, c.Redirect, c.RCE} {
		for _, u := range g {
			set[u] = true
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func mergeURLs(a, b []string) []string {
	set := map[string]bool{}
	for _, u := range a {
		set[u] = true
	}
	for _, u := range b {
		set[u] = true
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

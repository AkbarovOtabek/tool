// Package report собирает находки из store в отчёт Markdown + HTML.
package report

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"pentkit/internal/config"
	"pentkit/internal/store"
)

var sevOrder = []store.Severity{store.SevCritical, store.SevHigh, store.SevMedium, store.SevLow, store.SevInfo}

var sevRu = map[store.Severity]string{
	store.SevCritical: "Критические", store.SevHigh: "Высокие",
	store.SevMedium: "Средние", store.SevLow: "Низкие", store.SevInfo: "Инфо",
}

var sevColor = map[store.Severity]string{
	store.SevCritical: "#7c1d1d", store.SevHigh: "#b91c1c",
	store.SevMedium: "#b45309", store.SevLow: "#2563eb", store.SevInfo: "#475569",
}

var typeRu = map[string]string{
	store.TypeSubdomain: "Поддомены", store.TypeDNS: "DNS", store.TypePort: "Порты/сервисы",
	store.TypeHTTP: "HTTP-сервисы", store.TypeTech: "Технологии", store.TypeCloudflare: "Cloudflare",
	store.TypeOrigin: "Origin за Cloudflare", store.TypeVuln: "Уязвимости", store.TypeDir: "Директории",
	store.TypeParam: "Параметры/URL", store.TypeInjection: "Инъекции", store.TypeWAF: "WAF",
	store.TypeOSINT: "OSINT", store.TypeHeader: "Заголовки",
	store.TypeSecret: "Утечки секретов", store.TypeCORS: "CORS",
	store.TypeExposure: "Открытые файлы/интерфейсы",
	store.TypeJWT:      "JWT", store.TypeAPI: "API-эндпоинты",
	store.TypeAuth: "Аутентификация", store.TypeBypass: "Обход доступа",
	store.TypeLeak: "Утечки (OSINT)", store.TypeSmuggle: "Request smuggling",
	store.TypeAD: "Active Directory",
}

func typeLabel(t string) string {
	if v, ok := typeRu[t]; ok {
		return v
	}
	return t
}

// attackMap — соответствие типа находки технике MITRE ATT&CK (для раздела отчёта,
// понятного SOC клиента: по какой технике класс находки эксплуатируется).
var attackMap = map[string]string{
	store.TypeVuln:      "T1190 — Exploit Public-Facing Application",
	store.TypeInjection: "T1190 — Exploit Public-Facing Application",
	store.TypeOrigin:    "T1590 — Gather Victim Network Information (обход WAF/CDN)",
	store.TypeSecret:    "T1552 — Unsecured Credentials",
	store.TypeCORS:      "T1190 — Exploit Public-Facing Application",
	store.TypeDir:       "T1083 — File and Directory Discovery",
	store.TypeHeader:    "T1595 — Active Scanning / hardening",
}

// remediationMap — что порекомендовать клиенту закрыть, по типу находки.
var remediationMap = map[string]string{
	store.TypeVuln:      "Обновите уязвимый компонент до исправленной версии, примените патчи по CVE; закройте сервис снаружи, если он не нужен публично.",
	store.TypeInjection: "Используйте параметризованные запросы/ORM, валидируйте и экранируйте ввод; для RCE — обновите компонент и ограничьте права процесса.",
	store.TypeOrigin:    "Ограничьте доступ к origin только диапазонами Cloudflare (firewall allow CF), смените IP origin и уберите его утечки (DNS-история, favicon, SPF, старые A-записи).",
	store.TypeSecret:    "Немедленно отзовите утёкший ключ/токен, удалите из JS/репозитория, перейдите на серверное хранение секретов и ротацию.",
	store.TypeCORS:      "Задайте строгий allowlist Origin, не отражайте произвольный Origin и не ставьте Access-Control-Allow-Credentials с wildcard.",
	store.TypeDir:       "Закройте служебные/админские пути аутентификацией, отключите листинг директорий, уберите бэкап- и конфиг-файлы из публичного доступа.",
	store.TypeHeader:    "Добавьте security-заголовки (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) и скройте версии ПО в заголовках.",
}

// cvssBand — ориентировочный диапазон CVSS v3.1 по уровню (рейтинговые полосы
// FIRST). Это полоса важности, а не точный вектор — его считают вручную.
var cvssBand = map[store.Severity]string{
	store.SevCritical: "CVSS 9.0–10.0 (Critical)",
	store.SevHigh:     "CVSS 7.0–8.9 (High)",
	store.SevMedium:   "CVSS 4.0–6.9 (Medium)",
	store.SevLow:      "CVSS 0.1–3.9 (Low)",
	store.SevInfo:     "—",
}

func remediation(f store.Finding) string { return remediationMap[f.Type] }
func attack(f store.Finding) string      { return attackMap[f.Type] }

// Generate пишет report.md и report.html в каталог работы. Возвращает путь к HTML.
func Generate(cfg *config.Config, st *store.Store) (string, error) {
	findings := st.All()
	counts := st.Counts()

	md := buildMarkdown(cfg, findings, counts)
	mdPath := filepath.Join(st.Dir(), "report.md")
	if err := os.WriteFile(mdPath, []byte(md), 0o640); err != nil {
		return "", err
	}

	htmlDoc := buildHTML(cfg, findings, counts)
	htmlPath := filepath.Join(st.Dir(), "report.html")
	if err := os.WriteFile(htmlPath, []byte(htmlDoc), 0o640); err != nil {
		return "", err
	}
	return htmlPath, nil
}

// highlights считает заметные для резюме вещи.
func highlights(findings []store.Finding) (originsConfirmed, verifiedVulns, waf, emails int) {
	for _, f := range findings {
		for _, t := range f.Tags {
			switch t {
			case "origin-confirmed":
				originsConfirmed++
			case "verified":
				verifiedVulns++
			case "emails":
				emails++
			}
		}
		if f.Type == store.TypeWAF {
			waf++
		}
	}
	return
}

// surface — сводка поверхности атаки (что найдено по recon, даже без уязвимостей).
type surface struct {
	subsLive, subsResolve, subsDead int
	http, ports, tech, emails, cdn  int
}

func computeSurface(findings []store.Finding) surface {
	var s surface
	for _, f := range findings {
		has := func(tag string) bool {
			for _, t := range f.Tags {
				if t == tag {
					return true
				}
			}
			return false
		}
		switch f.Type {
		case store.TypeSubdomain:
			switch {
			case has("live"):
				s.subsLive++
			case has("dead"):
				s.subsDead++
			default:
				s.subsResolve++
			}
		case store.TypeHTTP:
			s.http++
		case store.TypePort:
			s.ports++
		case store.TypeTech:
			if has("cdn") || has("waf") {
				s.cdn++
			} else {
				s.tech++
			}
		case store.TypeOSINT:
			if has("emails") {
				s.emails++
			}
		}
	}
	return s
}

// surfaceItems возвращает подписи-значения для вывода (только ненулевые + поддомены).
func surfaceItems(s surface) [][2]string {
	var out [][2]string
	add := func(lbl string, n int, always bool) {
		if n > 0 || always {
			out = append(out, [2]string{lbl, itoaReport(n)})
		}
	}
	add("Живых поддоменов", s.subsLive, true)
	add("Резолвятся (не отвечают)", s.subsResolve, false)
	add("Мёртвых поддоменов", s.subsDead, false)
	add("HTTP-сервисов", s.http, false)
	add("Открытых портов", s.ports, false)
	add("Технологий", s.tech, false)
	add("За CDN/WAF", s.cdn, false)
	add("Почт (OSINT)", s.emails, false)
	return out
}

func itoaReport(n int) string { return fmt.Sprintf("%d", n) }

func execSummary(findings []store.Finding, counts map[store.Severity]int) string {
	oc, vv, waf, em := highlights(findings)
	var parts []string
	if n := counts[store.SevCritical]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d критических", n))
	}
	if n := counts[store.SevHigh]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d высоких", n))
	}
	if n := counts[store.SevMedium]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d средних", n))
	}
	head := "Значимых находок не выявлено."
	if len(parts) > 0 {
		head = "Выявлено: " + strings.Join(parts, ", ") + "."
	}
	var extra []string
	if waf > 0 {
		extra = append(extra, "периметр защищён WAF/CDN")
	}
	if oc > 0 {
		extra = append(extra, fmt.Sprintf("подтверждён(о) origin в обход Cloudflare: %d", oc))
	}
	if vv > 0 {
		extra = append(extra, fmt.Sprintf("перепроверенных срабатываний: %d", vv))
	}
	if em > 0 {
		extra = append(extra, "собраны почты (OSINT)")
	}
	if len(extra) > 0 {
		head += " " + capitalize(strings.Join(extra, "; ")) + "."
	}
	return head
}

func buildMarkdown(cfg *config.Config, findings []store.Finding, counts map[store.Severity]int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Отчёт о тестировании на проникновение\n\n")
	fmt.Fprintf(&b, "- **Клиент:** %s\n", cfg.Engagement.Client)
	fmt.Fprintf(&b, "- **Работа:** %s\n", cfg.Engagement.Name)
	fmt.Fprintf(&b, "- **Авторизация:** %s\n", cfg.Engagement.Authorization)
	fmt.Fprintf(&b, "- **Дата:** %s\n\n", time.Now().Format("2006-01-02 15:04"))

	fmt.Fprintf(&b, "## Резюме\n\n%s\n\n", execSummary(findings, counts))
	b.WriteString("| Уровень | Кол-во |\n|---|---|\n")
	for _, s := range sevOrder {
		fmt.Fprintf(&b, "| %s | %d |\n", sevRu[s], counts[s])
	}

	if items := surfaceItems(computeSurface(findings)); len(items) > 0 {
		b.WriteString("\n## Поверхность атаки\n\n")
		for _, it := range items {
			fmt.Fprintf(&b, "- **%s:** %s\n", it[0], it[1])
		}
	}
	b.WriteString("\n## Находки\n\n")

	// Значимые уровни — подробными пунктами.
	for _, s := range sevOrder {
		if s == store.SevInfo {
			continue
		}
		group := bySeverity(findings, s)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s (%d)\n\n", sevRu[s], len(group))
		for _, f := range group {
			fmt.Fprintf(&b, "- **%s** — `%s`\n", f.Title, f.Target)
			if f.Detail != "" {
				fmt.Fprintf(&b, "  - %s\n", f.Detail)
			}
			if f.Evidence != "" {
				fmt.Fprintf(&b, "  - _доказательство:_ %s\n", f.Evidence)
			}
			line := cvssBand[s]
			if a := attack(f); a != "" {
				line += " · ATT&CK: " + a
			}
			fmt.Fprintf(&b, "  - %s\n", line)
			if rem := remediation(f); rem != "" {
				fmt.Fprintf(&b, "  - 🛠 _Как исправить:_ %s\n", rem)
			}
			meta := f.Tool
			if len(f.Tags) > 0 {
				meta += " · " + strings.Join(f.Tags, ", ")
			}
			if meta != "" {
				fmt.Fprintf(&b, "  - _%s_\n", meta)
			}
		}
		b.WriteString("\n")
	}

	// Инфо (разведка) — компактно, сгруппировано по типу.
	info := bySeverity(findings, store.SevInfo)
	if len(info) > 0 {
		fmt.Fprintf(&b, "### Разведка и инфо (%d)\n\n", len(info))
		for _, grp := range byTypeGroups(info) {
			fmt.Fprintf(&b, "**%s (%d)**\n\n", typeLabel(grp.typ), len(grp.items))
			for _, f := range grp.items {
				fmt.Fprintf(&b, "- `%s` — %s\n", f.Target, f.Title)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Ручная проверка (бизнес-логика)\n\n")
	b.WriteString("_Автосканер это не находит — проверяется руками по своим тестовым аккаунтам._\n\n")
	for _, it := range manualChecklist {
		fmt.Fprintf(&b, "- [ ] **%s** — %s\n", it[0], it[1])
	}
	if dorks := googleDorks(cfg.Scope.Domains); len(dorks) > 0 {
		b.WriteString("\n## OSINT: Google-дорки\n\n")
		for _, d := range dorks {
			fmt.Fprintf(&b, "- [`%s`](%s)\n", d.query, d.url)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func buildHTML(cfg *config.Config, findings []store.Finding, counts map[store.Severity]int) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="ru"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	fmt.Fprintf(&b, "<title>Отчёт — %s</title>", html.EscapeString(cfg.Engagement.Name))
	b.WriteString(`<style>
:root{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--mut:#94a3b8;--line:#334155}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:24px 16px}
h1{font-size:22px}h2{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--mut)}.summary{background:var(--card);border-radius:10px;padding:14px 16px;margin:16px 0;font-size:15px}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.pill{padding:6px 12px;border-radius:999px;color:#fff;font-weight:600;font-size:13px}
.surf{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}
.sc{background:var(--card);border-radius:10px;padding:13px 15px;border-left:3px solid #6366f1}
.scn{font-size:23px;font-weight:800;line-height:1}
.scl{color:var(--mut);font-size:12px;margin-top:4px}
.f{background:var(--card);border-left:4px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
.f .t{font-weight:600}.f .tgt{color:var(--mut);font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
.f .d{color:var(--mut);font-size:14px;margin-top:4px}.tag{display:inline-block;background:#334155;color:#cbd5e1;border-radius:4px;padding:1px 6px;font-size:12px;margin-right:4px}
details{background:var(--card);border-radius:8px;margin:8px 0;padding:6px 12px}
summary{cursor:pointer;font-weight:600}
details table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
details td{padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
details td.k{color:var(--mut);font-family:ui-monospace,monospace;word-break:break-all;width:45%}
.rem{margin-top:6px;padding:8px 10px;background:#0f3d24;color:#bbf7d0;border-radius:6px;font-size:13px}
.exp{color:var(--mut);font-size:13px;margin:8px 0 0}
@media print{
  :root{--bg:#fff;--card:#f4f6fb;--fg:#111;--mut:#444;--line:#ccc}
  body{background:#fff}.f{break-inside:avoid}details{border:1px solid #ccc}.rem{background:#eafaf0;color:#14532d}
  .noprint{display:none}
}
</style></head><body><div class="wrap">`)
	fmt.Fprintf(&b, "<h1>Отчёт о тестировании на проникновение</h1>")
	fmt.Fprintf(&b, `<p class="meta">Клиент: %s · Работа: %s · Авторизация: %s · %s</p>`,
		html.EscapeString(cfg.Engagement.Client), html.EscapeString(cfg.Engagement.Name),
		html.EscapeString(cfg.Engagement.Authorization), time.Now().Format("2006-01-02 15:04"))

	fmt.Fprintf(&b, `<div class="summary">%s</div>`, html.EscapeString(execSummary(findings, counts)))
	b.WriteString(`<p class="exp noprint">Экспорт в PDF: Ctrl/Cmd+P → «Сохранить как PDF» (стили адаптированы под печать).</p>`)

	b.WriteString(`<div class="pills">`)
	for _, s := range sevOrder {
		fmt.Fprintf(&b, `<span class="pill" style="background:%s">%s: %d</span>`, sevColor[s], sevRu[s], counts[s])
	}
	b.WriteString(`</div>`)

	// Поверхность атаки — всегда полезная сводка recon, даже без уязвимостей.
	if items := surfaceItems(computeSurface(findings)); len(items) > 0 {
		b.WriteString(`<h2>Поверхность атаки</h2><div class="surf">`)
		for _, it := range items {
			fmt.Fprintf(&b, `<div class="sc"><div class="scn">%s</div><div class="scl">%s</div></div>`,
				html.EscapeString(it[1]), html.EscapeString(it[0]))
		}
		b.WriteString(`</div>`)
	}

	// Значимые уровни — карточками.
	for _, s := range sevOrder {
		if s == store.SevInfo {
			continue
		}
		group := bySeverity(findings, s)
		if len(group) == 0 {
			continue
		}
		fmt.Fprintf(&b, "<h2>%s (%d)</h2>", sevRu[s], len(group))
		for _, f := range group {
			fmt.Fprintf(&b, `<div class="f" style="border-left-color:%s">`, sevColor[s])
			fmt.Fprintf(&b, `<div class="t">%s</div><div class="tgt">%s</div>`,
				html.EscapeString(f.Title), html.EscapeString(f.Target))
			if f.Detail != "" {
				fmt.Fprintf(&b, `<div class="d">%s</div>`, html.EscapeString(f.Detail))
			}
			if f.Evidence != "" {
				fmt.Fprintf(&b, `<div class="d">Доказательство: %s</div>`, html.EscapeString(f.Evidence))
			}
			meta := []string{cvssBand[s]}
			if a := attack(f); a != "" {
				meta = append(meta, "ATT&CK: "+a)
			}
			fmt.Fprintf(&b, `<div class="d">%s</div>`, html.EscapeString(strings.Join(meta, " · ")))
			if rem := remediation(f); rem != "" {
				fmt.Fprintf(&b, `<div class="rem">🛠 Как исправить: %s</div>`, html.EscapeString(rem))
			}
			b.WriteString(`<div class="d">`)
			if f.Tool != "" {
				fmt.Fprintf(&b, `<span class="tag">%s</span>`, html.EscapeString(f.Tool))
			}
			for _, t := range f.Tags {
				fmt.Fprintf(&b, `<span class="tag">%s</span>`, html.EscapeString(t))
			}
			b.WriteString(`</div></div>`)
		}
	}

	// Инфо (разведка) — свёрнутые секции по типу, чтобы не захламлять отчёт.
	info := bySeverity(findings, store.SevInfo)
	if len(info) > 0 {
		fmt.Fprintf(&b, "<h2>Разведка и инфо (%d)</h2>", len(info))
		for _, grp := range byTypeGroups(info) {
			op := "" // небольшие/важные группы раскрываем сразу, длинные (поддомены) — свёрнуты
			if len(grp.items) <= 25 {
				op = " open"
			}
			fmt.Fprintf(&b, `<details%s><summary>%s (%d)</summary><table>`,
				op, html.EscapeString(typeLabel(grp.typ)), len(grp.items))
			for _, f := range grp.items {
				fmt.Fprintf(&b, `<tr><td class="k">%s</td><td>%s</td></tr>`,
					html.EscapeString(f.Target), html.EscapeString(f.Title))
			}
			b.WriteString(`</table></details>`)
		}
	}

	// Ручная проверка — то, что автосканеры не ловят (особенно важно для банков).
	b.WriteString(`<h2>Ручная проверка (бизнес-логика)</h2>`)
	b.WriteString(`<p class="meta">Автосканер это не находит — проверяется руками по своим тестовым аккаунтам.</p>`)
	b.WriteString(`<div class="f">`)
	for _, it := range manualChecklist {
		fmt.Fprintf(&b, `<div class="d">☐ <b>%s</b> — %s</div>`,
			html.EscapeString(it[0]), html.EscapeString(it[1]))
	}
	b.WriteString(`</div>`)

	// Google-дорки по доменам скоупа — пассивный OSINT.
	if dorks := googleDorks(cfg.Scope.Domains); len(dorks) > 0 {
		b.WriteString(`<h2>OSINT: Google-дорки</h2>`)
		b.WriteString(`<p class="meta">Пассивный поиск утёкших файлов/страниц — открой ссылки вручную.</p><div class="f">`)
		for _, d := range dorks {
			fmt.Fprintf(&b, `<div class="d"><a href="%s" target="_blank" rel="noopener">%s</a></div>`,
				html.EscapeString(d.url), html.EscapeString(d.query))
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`</div></body></html>`)
	return b.String()
}

// manualChecklist — чеклист ручной проверки бизнес-логики (вектор №1 для финсистем).
var manualChecklist = [][2]string{
	{"IDOR", "смена ID в запросе — доступ к чужим счетам, выпискам, документам"},
	{"Манипуляция суммой/валютой", "изменить amount/currency в запросе платежа (в т.ч. отрицательные и очень большие)"},
	{"Transaction replay", "повторить подписанный запрос перевода — проходит ли дважды"},
	{"Mass assignment", "добавить лишние поля (role, isAdmin, balance, status) в JSON — применяются ли"},
	{"Race condition (TOCTOU)", "параллельные запросы на вывод/списание — двойная трата"},
	{"2FA/OTP bypass", "пропуск шага подтверждения, брут/повтор OTP, слабая длина кода"},
	{"Privilege escalation", "горизонтальный (чужой объект) и вертикальный (функции админа) доступ"},
	{"Негативные сценарии", "операции без баланса, с чужой карты, после logout, с истёкшим токеном"},
}

type dork struct{ query, url string }

// googleDorks формирует типовые дорки по корневым доменам скоупа.
func googleDorks(domains []string) []dork {
	tmpl := []string{
		`site:%s filetype:pdf`,
		`site:%s (filetype:sql OR filetype:env OR filetype:log OR filetype:bak OR filetype:xls)`,
		`site:%s intitle:"index of"`,
		`site:%s (inurl:admin OR inurl:login OR inurl:dashboard)`,
		`site:%s ext:php inurl:?id=`,
		`site:pastebin.com %s`,
		`site:github.com %s password`,
	}
	var out []dork
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		for _, t := range tmpl {
			q := fmt.Sprintf(t, d)
			out = append(out, dork{query: q, url: "https://www.google.com/search?q=" + url.QueryEscape(q)})
		}
	}
	return out
}

func bySeverity(findings []store.Finding, s store.Severity) []store.Finding {
	var out []store.Finding
	for _, f := range findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

type typeGroup struct {
	typ   string
	items []store.Finding
}

// byTypeGroups группирует находки по типу, сохраняя стабильный порядок типов.
func byTypeGroups(findings []store.Finding) []typeGroup {
	idx := map[string]int{}
	var groups []typeGroup
	for _, f := range findings {
		i, ok := idx[f.Type]
		if !ok {
			idx[f.Type] = len(groups)
			groups = append(groups, typeGroup{typ: f.Type})
			i = len(groups) - 1
		}
		groups[i].items = append(groups[i].items, f)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return typeLabel(groups[i].typ) < typeLabel(groups[j].typ)
	})
	return groups
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s) // руны, а не байты — иначе ломается кириллица
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

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
}

func typeLabel(t string) string {
	if v, ok := typeRu[t]; ok {
		return v
	}
	return t
}

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

func execSummary(findings []store.Finding, counts map[store.Severity]int) string {
	oc, vv, _, em := highlights(findings)
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
.f{background:var(--card);border-left:4px solid var(--line);border-radius:8px;padding:12px 14px;margin:10px 0}
.f .t{font-weight:600}.f .tgt{color:var(--mut);font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
.f .d{color:var(--mut);font-size:14px;margin-top:4px}.tag{display:inline-block;background:#334155;color:#cbd5e1;border-radius:4px;padding:1px 6px;font-size:12px;margin-right:4px}
details{background:var(--card);border-radius:8px;margin:8px 0;padding:6px 12px}
summary{cursor:pointer;font-weight:600}
details table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
details td{padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
details td.k{color:var(--mut);font-family:ui-monospace,monospace;word-break:break-all;width:45%}
</style></head><body><div class="wrap">`)
	fmt.Fprintf(&b, "<h1>Отчёт о тестировании на проникновение</h1>")
	fmt.Fprintf(&b, `<p class="meta">Клиент: %s · Работа: %s · Авторизация: %s · %s</p>`,
		html.EscapeString(cfg.Engagement.Client), html.EscapeString(cfg.Engagement.Name),
		html.EscapeString(cfg.Engagement.Authorization), time.Now().Format("2006-01-02 15:04"))

	fmt.Fprintf(&b, `<div class="summary">%s</div>`, html.EscapeString(execSummary(findings, counts)))

	b.WriteString(`<div class="pills">`)
	for _, s := range sevOrder {
		fmt.Fprintf(&b, `<span class="pill" style="background:%s">%s: %d</span>`, sevColor[s], sevRu[s], counts[s])
	}
	b.WriteString(`</div>`)

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
			fmt.Fprintf(&b, `<details><summary>%s (%d)</summary><table>`,
				html.EscapeString(typeLabel(grp.typ)), len(grp.items))
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

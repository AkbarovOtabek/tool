// Package extra — дополнительные проверки: TLS (testssl), веб-сервер (nikto),
// subdomain takeover (nuclei), скриншоты (gowitness). Все необязательны: если
// тула нет — шаг пропускается, пайплайн не падает.
package extra

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

// TLS проверяет TLS-конфигурацию хостов через testssl.sh (берём первые maxHosts).
func TLS(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, hosts []string, maxHosts int) {
	if !rn.Has("testssl") && !rn.Has("testssl.sh") {
		ev.Logln("  ! testssl не установлен — пропускаю TLS-проверку")
		return
	}
	tool := "testssl"
	if !rn.Has("testssl") {
		tool = "testssl.sh"
	}
	for i, h := range hosts {
		if i >= maxHosts {
			break
		}
		r := rn.Run(ctx, tool, "--quiet", "--color", "0", "--severity", "LOW", h)
		for _, line := range r.Lines {
			up := strings.ToUpper(line)
			if strings.Contains(up, "VULNERABLE") || strings.Contains(up, "NOT OK") {
				sev := store.SevMedium
				if strings.Contains(up, "HIGH") || strings.Contains(up, "CRITICAL") {
					sev = store.SevHigh
				}
				st.Add(store.Finding{Target: h, Type: store.TypeVuln, Severity: sev,
					Title: "TLS: " + strings.TrimSpace(line), Tool: "testssl", Tags: []string{"tls"}})
			}
		}
		ev.Logf("  testssl: проверен %s\n", h)
	}
}

// Nikto прогоняет базовые проверки веб-сервера по URL (берём первые maxURLs).
func Nikto(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string, maxURLs int) {
	if rn.Passive || rn.Stealthy() {
		ev.Logln("  nikto пропущен: сигнатурный шумный скан — почти гарантированный триггер WAF/блок-листа")
		return
	}
	if !rn.Has("nikto") {
		ev.Logln("  ! nikto не установлен — пропускаю проверку веб-сервера")
		return
	}
	for i, u := range urls {
		if i >= maxURLs {
			break
		}
		r := rn.Run(ctx, "nikto", "-h", u, "-ask", "no", "-nointeractive")
		for _, line := range r.Lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "+ ") && !strings.Contains(line, "Target") && !strings.Contains(line, "Start Time") {
				st.Add(store.Finding{Target: u, Type: store.TypeVuln, Severity: store.SevLow,
					Title: "nikto: " + strings.TrimPrefix(line, "+ "), Tool: "nikto",
					Tags: []string{"requires-review"}})
			}
		}
		ev.Logf("  nikto: проверен %s\n", u)
	}
}

// Takeover ищет subdomain takeover через nuclei (теги takeover) и subzy.
func Takeover(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, hosts []string) {
	if len(hosts) == 0 {
		return
	}
	subzyTakeover(ctx, rn, st, ev, hosts)
	if !rn.Has("nuclei") {
		return
	}
	r := rn.RunStdin(ctx, strings.Join(hosts, "\n"), "nuclei", "-silent", "-tags", "takeover", "-jsonl")
	n := 0
	for _, line := range r.Lines {
		var t struct {
			TemplateID string `json:"template-id"`
			Host       string `json:"host"`
			MatchedAt  string `json:"matched-at"`
			Info       struct {
				Name string `json:"name"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(line), &t) != nil || t.TemplateID == "" {
			continue
		}
		// Цель — конкретный хост (а не литерал), иначе все находки схлопнутся дедупом.
		target := t.MatchedAt
		if target == "" {
			target = t.Host
		}
		title := "Возможный subdomain takeover"
		if t.Info.Name != "" {
			title += ": " + t.Info.Name
		}
		st.Add(store.Finding{Target: target, Type: store.TypeVuln, Severity: store.SevHigh,
			Title: title, Detail: "шаблон: " + t.TemplateID, Evidence: "matched-at: " + t.MatchedAt,
			Tool: "nuclei", Tags: []string{"takeover", "requires-review"}})
		n++
	}
	if n > 0 {
		ev.Logf("  takeover: кандидатов %d\n", n)
	} else {
		ev.Logln("  takeover: не найдено")
	}
}

// subzyTakeover — отдельный спец-тул под takeover: часто ловит то, что nuclei
// пропускает (своя база fingerprint'ов CNAME-сервисов). Цели передаём файлом.
func subzyTakeover(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, hosts []string) {
	if !rn.Has("subzy") {
		return
	}
	tf := filepath.Join(st.Dir(), "subzy-targets.txt")
	if err := os.WriteFile(tf, []byte(strings.Join(hosts, "\n")), 0o640); err != nil {
		ev.Logf("  ! subzy: не записал цели: %v\n", err)
		return
	}
	r := rn.Run(ctx, "subzy", "run", "--targets", tf, "--hide_fails", "--vuln")
	for _, line := range r.Lines {
		up := strings.ToUpper(line)
		if !strings.Contains(up, "VULNERABLE") {
			continue
		}
		st.Add(store.Finding{Target: extractHost(line), Type: store.TypeVuln, Severity: store.SevHigh,
			Title: "Возможный subdomain takeover (subzy)", Evidence: strings.TrimSpace(line),
			Tool: "subzy", Tags: []string{"takeover", "requires-review"}})
		ev.Logf("  subzy: %s\n", strings.TrimSpace(line))
	}
}

func extractHost(line string) string {
	if i := strings.Index(line, "http"); i >= 0 {
		rest := line[i:]
		if j := strings.IndexAny(rest, " \t]"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	for _, f := range strings.Fields(line) {
		if strings.Contains(f, ".") {
			return f
		}
	}
	return strings.TrimSpace(line)
}

// Screenshots делает скриншоты живых URL через gowitness (в подпапку screenshots).
func Screenshots(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if !rn.Has("gowitness") {
		ev.Logln("  ! gowitness не установлен — пропускаю скриншоты")
		return
	}
	if len(urls) == 0 {
		return
	}
	dir := filepath.Join(st.Dir(), "screenshots")
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "gowitness",
		"scan", "file", "-f", "-", "--screenshot-path", dir)
	if r.Err != nil {
		ev.Logf("  ! gowitness: %v\n", r.Err)
		return
	}
	st.Add(store.Finding{Target: dir, Type: store.TypeHTTP, Severity: store.SevInfo,
		Title: "Скриншоты сохранены", Detail: dir, Tool: "gowitness"})
	ev.Logf("  gowitness: скриншоты в %s\n", dir)
	_ = cfg
}

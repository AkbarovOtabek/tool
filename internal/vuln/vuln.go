// Package vuln — сканирование уязвимостей через nuclei с отсевом ложных срабатываний.
package vuln

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
}

var noisyTags = map[string]bool{"tech": true, "waf": true, "favicon": true}

func mapSeverity(s string) store.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return store.SevCritical
	case "high":
		return store.SevHigh
	case "medium":
		return store.SevMedium
	case "low":
		return store.SevLow
	default:
		return store.SevInfo
	}
}

// Run сканирует переданные URL через nuclei. verify=true включает перепроверку.
func Run(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string, verify bool) {
	if !rn.Has("nuclei") {
		ev.Logln("  ! nuclei не установлен — пропускаю скан уязвимостей")
		return
	}
	if len(urls) == 0 {
		ev.Logln("  нет живых URL для nuclei")
		return
	}

	rate := "150"
	if cfg.RateLimit > 0 {
		rate = strconv.Itoa(cfg.RateLimit)
	}
	nArgs := []string{"-silent", "-jsonl", "-severity", "low,medium,high,critical", "-rate-limit", rate}
	if rn.Stealthy() {
		// Меньше параллелизма и случайный User-Agent — тише для WAF/IPS.
		nArgs = append(nArgs, "-c", "10", "-timeout", "10", "-H", "User-Agent: "+netx.RandomUA())
	}
	r := rn.RunStdin(ctx, strings.Join(urls, "\n"), "nuclei", nArgs...)
	if r.Err != nil {
		ev.Logf("  ! nuclei: %v\n", r.Err)
	}

	type key struct{ tmpl, host string }
	seen := map[key]bool{}
	var hits []nucleiLine
	for _, line := range r.Lines {
		var n nucleiLine
		if json.Unmarshal([]byte(line), &n) != nil || n.TemplateID == "" {
			continue
		}
		k := key{n.TemplateID, n.Host}
		if seen[k] {
			continue
		}
		seen[k] = true
		hits = append(hits, n)
	}
	ev.Logf("  nuclei: уникальных срабатываний %d\n", len(hits))

	verified := map[key]bool{}
	if verify && len(hits) > 0 {
		ev.Logln("  перепроверяю срабатывания...")
		for _, n := range hits {
			vr := rn.Run(ctx, "nuclei", "-silent", "-jsonl", "-id", n.TemplateID, "-u", n.MatchedAt)
			for _, line := range vr.Lines {
				var v nucleiLine
				if json.Unmarshal([]byte(line), &v) == nil && v.TemplateID == n.TemplateID {
					verified[key{n.TemplateID, n.Host}] = true
				}
			}
		}
	}

	for _, n := range hits {
		sev := mapSeverity(n.Info.Severity)
		for _, t := range n.Info.Tags {
			if noisyTags[t] {
				sev = store.SevInfo
			}
		}
		tags := []string{n.TemplateID}
		if verify {
			if verified[key{n.TemplateID, n.Host}] {
				tags = append(tags, "verified")
			} else {
				tags = append(tags, "requires-review")
			}
		}
		st.Add(store.Finding{
			Target: n.MatchedAt, Type: store.TypeVuln, Severity: sev,
			Title: n.Info.Name, Detail: "шаблон: " + n.TemplateID,
			Evidence: "matched-at: " + n.MatchedAt, Tool: "nuclei", Tags: tags,
		})
	}
}

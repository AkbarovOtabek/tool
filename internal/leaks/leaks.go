// Package leaks — пассивный OSINT по внешним базам утечек (запросы идут к
// сторонним сервисам, не к цели):
//
//   - LeakIX (leakix.net) — утёкшие/открытые сервисы, конфиги, индексы по домену;
//   - IntelX (intelx.io) — утёкшие данные и credentials по домену.
//
// Оба требуют API-ключ (config.keys.leakix / intelx). Без ключа источник
// пропускается. Это только чтение сторонних баз — цель не трогается.
package leaks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/store"
)

const apiTO = 20 * time.Second

var client = &http.Client{Timeout: apiTO}

// Run запускает доступные источники по корневым доменам скоупа.
func Run(ctx context.Context, cfg *config.Config, st *store.Store, ev event.Sink, domains []string) {
	if cfg.Keys.LeakIX == "" && cfg.Keys.IntelX == "" {
		ev.Logln("  ! нет ключей LeakIX/IntelX — пропускаю (config.keys.leakix / intelx)")
		return
	}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if cfg.Keys.LeakIX != "" {
			leakix(ctx, cfg.Keys.LeakIX, st, ev, d)
		}
		if cfg.Keys.IntelX != "" {
			intelx(ctx, cfg.Keys.IntelX, st, ev, d)
		}
	}
}

// ---------- LeakIX ----------

type leakixEvent struct {
	Host      string   `json:"host"`
	Port      string   `json:"port"`
	Summary   string   `json:"summary"`
	Time      string   `json:"time"`
	EventType string   `json:"event_type"`
	Tags      []string `json:"tags"`
	Leak      struct {
		Severity string `json:"severity"`
		Dataset  struct {
			Rows int64 `json:"rows"`
		} `json:"dataset"`
	} `json:"leak"`
}

type leakixResp struct {
	Services []leakixEvent `json:"Services"`
	Leaks    []leakixEvent `json:"Leaks"`
}

func leakix(ctx context.Context, key string, st *store.Store, ev event.Sink, domain string) {
	body, code := apiGet(ctx, "https://leakix.net/domain/"+domain,
		map[string]string{"api-key": key, "Accept": "application/json"})
	if code != 200 {
		ev.Logf("  leakix %s: HTTP %d (пропуск)\n", domain, code)
		return
	}
	var r leakixResp
	if json.Unmarshal(body, &r) != nil {
		return
	}
	n := parseLeakix(st, domain, r)
	ev.Logf("  leakix %s: событий %d\n", domain, n)
}

// parseLeakix раскладывает ответ LeakIX в находки (вынесено для юнит-тестов).
func parseLeakix(st *store.Store, domain string, r leakixResp) int {
	n := 0
	for _, e := range r.Leaks {
		sev := mapLeakSev(e.Leak.Severity)
		detail := e.Summary
		if e.Leak.Dataset.Rows > 0 {
			detail = fmt.Sprintf("строк в датасете: %d. %s", e.Leak.Dataset.Rows, detail)
		}
		st.Add(store.Finding{Target: hostOr(e.Host, domain), Type: store.TypeLeak, Severity: sev,
			Title:  "LeakIX: утечка " + firstNonEmpty(e.EventType, "данных"),
			Detail: trim(detail, 300), Evidence: joinTags(e.Tags),
			Tool: "leakix", Tags: []string{"leak", "osint", "requires-review"}})
		n++
	}
	for _, e := range r.Services {
		// Открытые сервисы — информативно (поверхность), severity ниже.
		st.Add(store.Finding{Target: hostOr(e.Host, domain), Type: store.TypeLeak, Severity: store.SevInfo,
			Title:  "LeakIX: открытый сервис " + firstNonEmpty(e.EventType, e.Port),
			Detail: trim(e.Summary, 300), Tool: "leakix", Tags: []string{"leak", "osint"}})
		n++
	}
	return n
}

func mapLeakSev(s string) store.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return store.SevCritical
	case "high":
		return store.SevHigh
	case "medium":
		return store.SevMedium
	case "low":
		return store.SevLow
	default:
		return store.SevMedium // сам факт утечки — минимум medium
	}
}

// ---------- IntelX ----------

type intelxSearchStart struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
}

type intelxRecord struct {
	Name   string `json:"name"`
	Date   string `json:"date"`
	Bucket string `json:"bucket"`
	Media  int    `json:"media"`
}

type intelxResult struct {
	Records []intelxRecord `json:"records"`
	Status  int            `json:"status"` // 0 = есть ещё, 1 = готово, >1 = нет данных
}

func intelx(ctx context.Context, key string, st *store.Store, ev event.Sink, domain string) {
	// 1) стартуем поиск
	start, code := apiPostJSON(ctx, "https://2.intelx.io/intelligent/search",
		map[string]string{"x-key": key},
		map[string]any{"term": domain, "maxresults": 100, "media": 0, "sort": 4, "timeout": 10})
	if code != 200 {
		ev.Logf("  intelx %s: старт HTTP %d (пропуск)\n", domain, code)
		return
	}
	var s intelxSearchStart
	if json.Unmarshal(start, &s) != nil || s.ID == "" {
		return
	}
	// 2) забираем результаты (несколько опросов, пока статус не «готово»)
	recs := intelxCollect(ctx, key, s.ID)
	if len(recs) == 0 {
		ev.Logf("  intelx %s: записей не найдено\n", domain)
		return
	}
	buckets := map[string]bool{}
	var sample []string
	for _, r := range recs {
		buckets[r.Bucket] = true
		if len(sample) < 8 && r.Name != "" {
			sample = append(sample, r.Name)
		}
	}
	st.Add(store.Finding{Target: domain, Type: store.TypeLeak, Severity: store.SevMedium,
		Title:    fmt.Sprintf("IntelX: найдено записей %d в %d коллекциях", len(recs), len(buckets)),
		Detail:   "коллекции: " + strings.Join(keysOf(buckets), ", "),
		Evidence: "примеры: " + trim(strings.Join(sample, " | "), 300),
		Tool:     "intelx", Tags: []string{"leak", "osint", "requires-review"}})
	ev.Logf("  intelx %s: записей %d\n", domain, len(recs))
}

func intelxCollect(ctx context.Context, key, id string) []intelxRecord {
	var all []intelxRecord
	for i := 0; i < 6; i++ {
		body, code := apiGet(ctx, "https://2.intelx.io/intelligent/search/result?id="+id+"&limit=100",
			map[string]string{"x-key": key})
		if code != 200 {
			break
		}
		var res intelxResult
		if json.Unmarshal(body, &res) != nil {
			break
		}
		all = append(all, res.Records...)
		if res.Status == 1 || res.Status > 1 { // 1 = завершено, >1 = нет данных
			break
		}
		select {
		case <-ctx.Done():
			return all
		case <-time.After(1500 * time.Millisecond):
		}
	}
	return all
}

// ---------- HTTP-утилиты ----------

func apiGet(ctx context.Context, url string, headers map[string]string) ([]byte, int) {
	return apiDo(ctx, http.MethodGet, url, headers, nil)
}

func apiPostJSON(ctx context.Context, url string, headers map[string]string, payload any) ([]byte, int) {
	b, _ := json.Marshal(payload)
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	return apiDo(ctx, http.MethodPost, url, headers, b)
}

func apiDo(ctx context.Context, method, url string, headers map[string]string, body []byte) ([]byte, int) {
	cctx, cancel := context.WithTimeout(ctx, apiTO)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(cctx, method, url, rd)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("User-Agent", "pentkit-osint")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	return b, resp.StatusCode
}

func hostOr(h, d string) string {
	if strings.TrimSpace(h) != "" {
		return h
	}
	return d
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func joinTags(t []string) string {
	if len(t) == 0 {
		return ""
	}
	return "tags: " + strings.Join(t, ", ")
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

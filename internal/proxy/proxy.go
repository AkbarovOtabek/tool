package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"pentkit/internal/netx"
)

const (
	maxBodyCapture = 2 << 20          // сколько байт тела читать (и форвардить)
	maxReqStore    = 256 << 10        // сколько байт сырого запроса хранить (для Repeater)
	maxRespStore   = 64 << 10         // сколько байт сырого ответа хранить (для показа)
	maxHistory     = 2000             // кольцевой предел записей истории
	interceptHold  = 5 * time.Minute
)

func capStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[обрезано pentkit]"
	}
	return s
}

// Entry — одна пара запрос/ответ в истории прокси.
type Entry struct {
	ID        int       `json:"id"`
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	Scheme    string    `json:"scheme"`
	Host      string    `json:"host"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	MIME      string    `json:"mime"`
	Length    int       `json:"length"`
	InScope   bool      `json:"in_scope"`
	Notes     []string  `json:"notes,omitempty"`
	ReqRaw    string    `json:"req_raw,omitempty"`
	RespRaw   string    `json:"resp_raw,omitempty"`
}

// pending — запрос, удержанный в режиме Intercept.
type pending struct {
	ID     int
	Scheme string
	Host   string
	Raw    string
	done   chan decision
}

type decision struct {
	drop bool
	raw  string // отредактированный сырой запрос (пусто = без изменений)
}

// ScopeChecker — необязательная проверка принадлежности хоста скоупу.
type ScopeChecker interface {
	InScope(host string) bool
}

// Proxy — перехватывающий прокси.
type Proxy struct {
	ca    *CA
	tr    *http.Transport
	scope ScopeChecker

	mu          sync.Mutex
	history     []*Entry
	nextID      int
	interceptOn bool
	pendings    map[int]*pending

	srv  *http.Server
	ln   net.Listener
	addr string
}

// New создаёт прокси. caDir — где хранить/искать корневой CA; scope может быть nil.
func New(caDir string, scope ScopeChecker) (*Proxy, error) {
	ca, err := LoadOrCreateCA(caDir)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		ca:       ca,
		scope:    scope,
		pendings: map[int]*pending{},
		tr: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableCompression:  true, // тело передаём как есть, не распаковывая
			DisableKeepAlives:   false,
			MaxIdleConns:        100,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}, nil
}

// SetUpstreamProxy направляет исходящие соединения прокси (к реальным сайтам)
// через SOCKS5 (Tor), чтобы и ручной перехват ходил анонимно. "" — напрямую.
func (p *Proxy) SetUpstreamProxy(socksAddr string) {
	if socksAddr == "" {
		return
	}
	d := netx.NewDialer(socksAddr, 15*time.Second)
	p.tr.DialContext = d.DialContext
}

// Start поднимает прокси на addr (например, 127.0.0.1:8780).
func (p *Proxy) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.ln = ln
	p.addr = ln.Addr().String()
	p.srv = &http.Server{Handler: p}
	go p.srv.Serve(ln)
	return nil
}

// Stop останавливает прокси.
func (p *Proxy) Stop() {
	if p.srv != nil {
		p.srv.Close()
	}
	if p.ln != nil {
		p.ln.Close()
	}
}

// Addr — фактический адрес прослушивания.
func (p *Proxy) Addr() string { return p.addr }

// CACertPEM — корневой сертификат для импорта в браузер.
func (p *Proxy) CACertPEM() []byte { return p.ca.CertPEM() }

// SetIntercept включает/выключает удержание запросов.
func (p *Proxy) SetIntercept(on bool) {
	p.mu.Lock()
	p.interceptOn = on
	// при выключении отпускаем всё удержанное без изменений
	if !on {
		for _, pr := range p.pendings {
			select {
			case pr.done <- decision{}:
			default:
			}
		}
	}
	p.mu.Unlock()
}

// Intercepting сообщает текущий режим.
func (p *Proxy) Intercepting() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interceptOn
}

// ServeHTTP — точка входа прокси (CONNECT = HTTPS MITM, иначе plain HTTP).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

// handlePlain проксирует обычный HTTP (не CONNECT).
func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := readCapped(r.Body)
	r.Body.Close()

	scheme := "http"
	host := r.Host
	rawReq := rawRequest(r, scheme, reqBody)

	dec := p.maybeIntercept(scheme, host, rawReq)
	if dec.drop {
		http.Error(w, "dropped by pentkit proxy", http.StatusForbidden)
		return
	}
	outReq := r
	if dec.raw != "" {
		if nr := parseRaw(r.Context(), dec.raw, scheme, host); nr != nil {
			outReq = nr
			rawReq = dec.raw
		}
	} else {
		outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	resp, err := p.roundtrip(outReq, scheme, host)
	if err != nil {
		http.Error(w, "proxy: "+err.Error(), http.StatusBadGateway)
		p.record(outReq, scheme, host, rawReq, 0, nil, nil, err)
		return
	}
	respBody, _ := readCapped(resp.Body)
	resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
	p.record(outReq, scheme, host, rawReq, resp.StatusCode, resp.Header, respBody, nil)
}

// handleConnect терминирует TLS (MITM) и проксирует HTTPS-запросы.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack не поддерживается", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	connectHost := r.Host // host:port

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConf := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = stripPort(connectHost)
			}
			return p.ca.LeafFor(name)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConf)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	authority := connectHost // host:port — на него и форвардим (порт может быть не 443)
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		// Апгрейды (WebSocket) не MITM-им — закрываем.
		if strings.EqualFold(req.Header.Get("Connection"), "upgrade") {
			return
		}
		reqBody, _ := readCapped(req.Body)
		req.Body.Close()
		rawReq := rawRequest(req, "https", reqBody)

		dec := p.maybeIntercept("https", authority, rawReq)
		if dec.drop {
			writeRaw(tlsConn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			continue
		}
		outReq := req
		if dec.raw != "" {
			if nr := parseRaw(context.Background(), dec.raw, "https", authority); nr != nil {
				outReq = nr
				rawReq = dec.raw
			}
		} else {
			outReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		resp, err := p.roundtrip(outReq, "https", authority)
		if err != nil {
			writeRaw(tlsConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			p.record(outReq, "https", authority, rawReq, 0, nil, nil, err)
			continue
		}
		respBody, _ := readCapped(resp.Body)
		resp.Body.Close()
		writeResponse(tlsConn, resp, respBody)
		p.record(outReq, "https", authority, rawReq, resp.StatusCode, resp.Header, respBody, nil)
	}
}

// roundtrip отправляет запрос на реальный сервер.
func (p *Proxy) roundtrip(req *http.Request, scheme, host string) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.RequestURI = ""
	out.URL.Scheme = scheme
	if out.URL.Host == "" {
		out.URL.Host = host
	}
	if out.Host == "" {
		out.Host = host
	}
	return p.tr.RoundTrip(out)
}

// maybeIntercept при включённом режиме удерживает запрос до решения оператора.
func (p *Proxy) maybeIntercept(scheme, host, raw string) decision {
	p.mu.Lock()
	if !p.interceptOn {
		p.mu.Unlock()
		return decision{}
	}
	p.nextID++
	id := p.nextID
	pr := &pending{ID: id, Scheme: scheme, Host: host, Raw: raw, done: make(chan decision, 1)}
	p.pendings[id] = pr
	p.mu.Unlock()

	var d decision
	select {
	case d = <-pr.done:
	case <-time.After(interceptHold):
	}
	p.mu.Lock()
	delete(p.pendings, id)
	p.mu.Unlock()
	return d
}

// Pending возвращает удержанные запросы (для UI).
func (p *Proxy) Pending() []*pending {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*pending, 0, len(p.pendings))
	for _, pr := range p.pendings {
		out = append(out, pr)
	}
	return out
}

// Resolve принимает решение по удержанному запросу (forward с правкой или drop).
func (p *Proxy) Resolve(id int, drop bool, raw string) bool {
	p.mu.Lock()
	pr, ok := p.pendings[id]
	p.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case pr.done <- decision{drop: drop, raw: raw}:
		return true
	default:
		return false
	}
}

// record сохраняет пару запрос/ответ в историю + пассивные заметки.
func (p *Proxy) record(req *http.Request, scheme, host, rawReq string, status int, respHdr http.Header, respBody []byte, callErr error) {
	inScope := true
	if p.scope != nil {
		inScope = p.scope.InScope(stripPort(host))
	}
	e := &Entry{
		Time: time.Now(), Method: req.Method, Scheme: scheme, Host: host,
		URL: req.URL.RequestURI(), Status: status, InScope: inScope,
		Length: len(respBody), ReqRaw: capStr(rawReq, maxReqStore),
	}
	if callErr != nil {
		e.Notes = append(e.Notes, "ошибка: "+callErr.Error())
	}
	if respHdr != nil {
		e.MIME = respHdr.Get("Content-Type")
		e.RespRaw = capStr(rawResponse(status, respHdr, respBody), maxRespStore)
		e.Notes = append(e.Notes, passiveNotes(scheme, respHdr)...)
	}
	p.mu.Lock()
	p.nextID++
	e.ID = p.nextID
	p.history = append(p.history, e)
	if len(p.history) > maxHistory {
		p.history = p.history[len(p.history)-maxHistory:]
	}
	p.mu.Unlock()
}

// History возвращает историю (summary без тел, если full=false).
func (p *Proxy) History(full bool) []*Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Entry, 0, len(p.history))
	for i := len(p.history) - 1; i >= 0; i-- { // новые сверху
		e := p.history[i]
		if full {
			out = append(out, e)
			continue
		}
		out = append(out, &Entry{ID: e.ID, Time: e.Time, Method: e.Method,
			Scheme: e.Scheme, Host: e.Host, URL: e.URL, Status: e.Status,
			MIME: e.MIME, Length: e.Length, InScope: e.InScope, Notes: e.Notes})
	}
	return out
}

// Get возвращает одну запись истории целиком.
func (p *Proxy) Get(id int) *Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.history {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Count — размер истории.
func (p *Proxy) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.history)
}

// RepeatResult — ответ на отправку из Repeater.
type RepeatResult struct {
	Status  int    `json:"status"`
	RespRaw string `json:"resp_raw"`
	Length  int    `json:"length"`
	Err     string `json:"err,omitempty"`
}

// Repeat отправляет произвольный сырой запрос (Repeater) и возвращает ответ.
func (p *Proxy) Repeat(scheme, host, raw string) RepeatResult {
	req := parseRaw(context.Background(), raw, scheme, host)
	if req == nil {
		return RepeatResult{Err: "не удалось разобрать запрос"}
	}
	resp, err := p.roundtrip(req, scheme, host)
	if err != nil {
		return RepeatResult{Err: err.Error()}
	}
	body, _ := readCapped(resp.Body)
	resp.Body.Close()
	e := &Entry{Time: time.Now(), Method: req.Method, Scheme: scheme, Host: host,
		URL: req.URL.RequestURI(), Status: resp.StatusCode, Length: len(body),
		MIME: resp.Header.Get("Content-Type"), InScope: p.inScope(host),
		ReqRaw: capStr(raw, maxReqStore), RespRaw: capStr(rawResponse(resp.StatusCode, resp.Header, body), maxRespStore),
		Notes: []string{"repeater"}}
	p.mu.Lock()
	p.nextID++
	e.ID = p.nextID
	p.history = append(p.history, e)
	p.mu.Unlock()
	return RepeatResult{Status: resp.StatusCode, RespRaw: e.RespRaw, Length: len(body)}
}

func (p *Proxy) inScope(host string) bool {
	if p.scope == nil {
		return true
	}
	return p.scope.InScope(stripPort(host))
}

// --- вспомогательные функции ---

func passiveNotes(scheme string, h http.Header) []string {
	var notes []string
	if scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		notes = append(notes, "нет HSTS")
	}
	if h.Get("Content-Security-Policy") == "" {
		notes = append(notes, "нет CSP")
	}
	if s := h.Get("Server"); s != "" {
		notes = append(notes, "Server: "+s)
	}
	if s := h.Get("Set-Cookie"); s != "" && !strings.Contains(strings.ToLower(s), "httponly") {
		notes = append(notes, "cookie без HttpOnly")
	}
	return notes
}

func readCapped(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(r, maxBodyCapture))
}

func rawRequest(r *http.Request, scheme string, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	if r.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	}
	for k, vals := range r.Header {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

func rawResponse(status int, h http.Header, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for k, vals := range h {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// parseRaw разбирает сырой HTTP-запрос (как из Repeater/правки Intercept).
func parseRaw(ctx context.Context, raw, scheme, host string) *http.Request {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	idx := strings.Index(raw, "\n\n")
	head := raw
	body := ""
	if idx >= 0 {
		head = raw[:idx]
		body = raw[idx+2:]
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil
	}
	method, path := parts[0], parts[1]
	hdr := http.Header{}
	hHost := host
	for _, line := range lines[1:] {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.TrimSpace(line[i+1:])
		if strings.EqualFold(k, "Host") {
			hHost = v
			continue
		}
		if strings.EqualFold(k, "Content-Length") {
			continue // пересчитает http-клиент
		}
		hdr.Add(k, v)
	}
	// Строка запроса может быть origin-form (/path) или absolute-form (http://host/path).
	target := scheme + "://" + hHost + path
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		target = path
	}
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header = hdr
	req.Host = hHost
	return req
}

func writeRaw(w io.Writer, s string) { _, _ = w.Write([]byte(s)) }

func writeResponse(w io.Writer, resp *http.Response, body []byte) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, vals := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("\r\n")
	_, _ = w.Write([]byte(b.String()))
	_, _ = w.Write(body)
}

// PendingView — публичное представление удержанного запроса для JSON.
type PendingView struct {
	ID     int    `json:"id"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Raw    string `json:"raw"`
}

// PendingList возвращает удержанные запросы в виде, пригодном для JSON.
func (p *Proxy) PendingList() []PendingView {
	var out []PendingView
	for _, pr := range p.Pending() {
		out = append(out, PendingView{ID: pr.ID, Scheme: pr.Scheme, Host: pr.Host, Raw: pr.Raw})
	}
	return out
}

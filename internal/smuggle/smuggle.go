// Package smuggle — детект HTTP Request Smuggling (CL.TE / TE.CL) по таймингам.
//
// ВНИМАНИЕ: это активная и потенциально рискованная проверка. Она шлёт
// намеренно неоднозначные (Content-Length + Transfer-Encoding) запросы, которые
// на уязвимой связке «фронт-прокси ↔ бэкенд» вызывают рассинхрон. Используется
// БЕЗОПАСНЫЙ таймингов­ый вариант: мы НЕ протаскиваем вторую «боевую» заявку, а
// лишь замеряем задержку — уязвимый бэкенд зависает в ожидании тела. Тем не
// менее на хрупких прокси это может повлиять на обработку запросов, поэтому:
//   - проверка выключена по умолчанию и не входит в AllOn;
//   - пропускается в пассивном режиме;
//   - бьёт только по корню каждого хоста (малый объём).
//
// Детект эвристический: находка = «кандидат», требует ручного подтверждения.
package smuggle

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"

	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

const (
	dialTO     = 10 * time.Second
	readTO     = 12 * time.Second // сколько ждём ответ на пробу
	delayFlag  = 5 * time.Second  // задержка пробы, считающаяся подозрительной
	maxTargets = 20
)

// Run прогоняет timing-пробы CL.TE/TE.CL по корню каждого хоста из urls.
func Run(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, urls []string) {
	if rn.Passive {
		ev.Logln("  пассивный режим: smuggling-пробы пропущены")
		return
	}
	hosts := uniqueRoots(urls)
	if len(hosts) > maxTargets {
		hosts = hosts[:maxTargets]
	}
	if len(hosts) == 0 {
		return
	}
	ev.Logf("  smuggling: timing-пробы CL.TE/TE.CL по %d хостам...\n", len(hosts))
	n := 0
	for _, u := range hosts {
		host, port, secure, ok := hostPort(u)
		if !ok {
			continue
		}
		// База — обычный полный запрос, должен отвечать быстро.
		base, err := probe(ctx, rn, host, port, secure, baselineReq(host))
		if err != nil || base > delayFlag {
			continue // недоступен или и так медленный — пропускаем, чтобы не ложить FP
		}
		for _, p := range []struct{ name, raw string }{
			{"CL.TE", clteReq(host)},
			{"TE.CL", teclReq(host)},
		} {
			d, err := probe(ctx, rn, host, port, secure, p.raw)
			if err != nil {
				continue
			}
			if d >= delayFlag && d >= base+4*time.Second {
				st.Add(store.Finding{Target: u, Type: store.TypeSmuggle, Severity: store.SevHigh,
					Title:    "Кандидат на HTTP Request Smuggling (" + p.name + ")",
					Detail:   "проба зависла на " + d.Round(time.Millisecond).String() + " (база " + base.Round(time.Millisecond).String() + ") — признак рассинхрона фронт/бэкенд",
					Evidence: "тайминговый детект " + p.name + "; подтверди вручную (Burp Repeater/smuggler) перед эксплуатацией",
					Tool:     "smuggle", Tags: []string{"smuggling", "desync", "requires-review"}})
				ev.Logf("  smuggling: кандидат %s на %s (%.1fs vs база %.1fs)\n", p.name, u, d.Seconds(), base.Seconds())
				n++
				break // одного сигнала на хост достаточно
			}
		}
	}
	ev.Logf("  smuggling: кандидатов %d\n", n)
}

// probe открывает соединение (с учётом Tor/SOCKS), шлёт raw-запрос и замеряет
// время до первого байта ответа.
func probe(ctx context.Context, rn *runner.Runner, host, port string, secure bool, raw string) (time.Duration, error) {
	cctx, cancel := context.WithTimeout(ctx, dialTO+readTO)
	defer cancel()

	var conn net.Conn
	var err error
	addr := net.JoinHostPort(host, port)
	if rn.SOCKS != "" {
		conn, err = netx.NewDialer(rn.SOCKS, dialTO).DialContext(cctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{Timeout: dialTO}).DialContext(cctx, "tcp", addr)
	}
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if secure {
		tconn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		tconn.SetDeadline(time.Now().Add(dialTO))
		if err := tconn.Handshake(); err != nil {
			return 0, err
		}
		conn = tconn
	}

	conn.SetDeadline(time.Now().Add(readTO))
	start := time.Now()
	if _, err := conn.Write([]byte(raw)); err != nil {
		return 0, err
	}
	// Ждём первую строку ответа; уязвимый бэкенд будет держать паузу.
	br := bufio.NewReader(conn)
	_, err = br.ReadString('\n')
	elapsed := time.Since(start)
	if err != nil {
		// таймаут чтения = сервер завис на пробе: это и есть сигнал.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return readTO, nil
		}
		return elapsed, err
	}
	return elapsed, nil
}

// --- raw-запросы (CRLF обязателен) ---

func baselineReq(host string) string {
	return "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: pentkit-smuggle\r\n" +
		"Connection: close\r\n\r\n"
}

// clteReq: фронт считает по Content-Length (4 байта), бэкенд — по chunked и ждёт
// следующий чанк → зависание на уязвимой CL.TE-связке.
func clteReq(host string) string {
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: pentkit-smuggle\r\n" +
		"Content-Length: 4\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"1\r\nA\r\nX"
}

// teclReq: бэкенд считает по Content-Length (6), фронт — по chunked (видит 0\r\n\r\n
// как конец) → бэкенд ждёт недостающие байты на уязвимой TE.CL-связке.
func teclReq(host string) string {
	return "POST / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: pentkit-smuggle\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		"0\r\n\r\nX"
}

// --- утилиты ---

func uniqueRoots(urls []string) []string {
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

// hostPort раскладывает URL на host, port, secure(https).
func hostPort(raw string) (host, port string, secure, ok bool) {
	p, err := url.Parse(raw)
	if err != nil || p.Hostname() == "" {
		return "", "", false, false
	}
	secure = p.Scheme == "https"
	host = p.Hostname()
	port = p.Port()
	if port == "" {
		if secure {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port, secure, true
}

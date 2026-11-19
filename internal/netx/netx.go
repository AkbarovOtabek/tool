// Package netx — сетевой слой скрытности: SOCKS5-клиент для маршрутизации
// Go-трафика через Tor/прокси, генерация конфига proxychains4 для внешних тулов,
// проверка доступности прокси и ротация User-Agent.
//
// SOCKS5-клиент — минимальный, на чистой stdlib (без x/net/proxy), без
// аутентификации (метод 0x00), чего достаточно для локального Tor (9050) и
// любого SOCKS5 без логина/пароля.
package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Dialer открывает TCP-соединения через SOCKS5-прокси.
type Dialer struct {
	Proxy   string        // адрес SOCKS5 (host:port)
	Timeout time.Duration // таймаут установления соединения и рукопожатия
}

// NewDialer создаёт SOCKS5-диалер.
func NewDialer(proxy string, timeout time.Duration) *Dialer {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Dialer{Proxy: proxy, Timeout: timeout}
}

// DialContext соединяется с addr ЧЕРЕЗ SOCKS5-прокси. Если host в addr —
// доменное имя, оно резолвится на стороне прокси (ATYP=domain), что исключает
// утечку DNS мимо Tor.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5: поддерживается только tcp, не %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: разбор адреса %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: неверный порт %q", portStr)
	}

	dl := &net.Dialer{Timeout: d.Timeout}
	conn, err := dl.DialContext(ctx, "tcp", d.Proxy)
	if err != nil {
		return nil, fmt.Errorf("socks5: нет связи с прокси %s: %w", d.Proxy, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(d.Timeout))
	}

	// 1. Выбор метода: VER=5, NMETHODS=1, METHOD=0 (без аутентификации).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: отправка метода: %w", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: ответ метода: %w", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: прокси не принял метод без аутентификации (0x%02x)", rep[1])
	}

	// 2. Запрос CONNECT.
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("socks5: имя хоста слишком длинное")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: отправка CONNECT: %w", err)
	}

	// 3. Ответ: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: ответ CONNECT: %w", err)
	}
	if head[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: неверная версия ответа 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: прокси отклонил соединение: %s", socksReply(head[1]))
	}
	// Дочитываем BND.ADDR+BND.PORT, чтобы оставить поток в чистом состоянии.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(l[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: неизвестный ATYP 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{}) // снимаем дедлайн рукопожатия
	return conn, nil
}

func socksReply(code byte) string {
	switch code {
	case 0x01:
		return "общий сбой SOCKS-сервера"
	case 0x02:
		return "соединение запрещено правилами"
	case 0x03:
		return "сеть недоступна"
	case 0x04:
		return "хост недоступен (exit-нода не достучалась до цели)"
	case 0x05:
		return "соединение отклонено"
	case 0x06:
		return "истёк TTL"
	case 0x07:
		return "команда не поддерживается"
	case 0x08:
		return "тип адреса не поддерживается"
	default:
		return fmt.Sprintf("код 0x%02x", code)
	}
}

// HTTPClient строит http.Client, ходящий через SOCKS5-прокси.
// insecureTLS=true — не проверять сертификаты (origin/самоподписанные).
func HTTPClient(proxy string, timeout time.Duration, insecureTLS bool) *http.Client {
	d := NewDialer(proxy, 10*time.Second)
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:       d.DialContext,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecureTLS},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Normalize приводит адрес прокси к host:port, срезая схему socks5[h]://.
func Normalize(proxy string) string {
	p := strings.TrimSpace(proxy)
	p = strings.TrimPrefix(p, "socks5h://")
	p = strings.TrimPrefix(p, "socks5://")
	return strings.TrimSuffix(p, "/")
}

// Check проверяет, что по адресу отвечает SOCKS5-прокси (рукопожатие без
// аутентификации). Быстрый фейл до старта сканирования, если Tor не запущен.
// EnsureTor проверяет, слушает ли Tor на proxy (host:port), и если нет —
// пытается стартовать системный сервис tor (systemctl/service, c sudo при
// необходимости) и ждёт появления порта. Возвращает true, если Tor доступен.
// log получает короткие статусные строки (может быть nil).
func EnsureTor(proxy string, log func(string)) bool {
	if Check(proxy, 2*time.Second) == nil {
		return true
	}
	if log != nil {
		log("Tor не запущен — стартую сервис tor...")
	}
	var prefix []string
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err == nil {
			prefix = []string{"sudo", "-n"}
		}
	}
	for _, c := range [][]string{
		{"systemctl", "start", "tor"},
		{"service", "tor", "start"},
		{"systemctl", "start", "tor@default"},
	} {
		argv := append(append([]string{}, prefix...), c...)
		if _, err := exec.LookPath(argv[0]); err != nil {
			continue
		}
		_ = exec.Command(argv[0], argv[1:]...).Run()
		for i := 0; i < 8; i++ {
			if Check(proxy, 2*time.Second) == nil {
				if log != nil {
					log("Tor запущен ✓")
				}
				return true
			}
			time.Sleep(time.Second)
		}
	}
	if log != nil {
		log("не удалось автоматически запустить Tor (запусти вручную: sudo systemctl start tor)")
	}
	return Check(proxy, 2*time.Second) == nil
}

func Check(proxy string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", proxy)
	if err != nil {
		return fmt.Errorf("нет связи с %s: %w", proxy, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return fmt.Errorf("%s не ответил как SOCKS5: %w", proxy, err)
	}
	if rep[0] != 0x05 {
		return fmt.Errorf("%s не похож на SOCKS5-прокси (ответ 0x%02x)", proxy, rep[0])
	}
	return nil
}

// WriteProxychainsConf пишет конфиг proxychains4, указывающий на заданный
// SOCKS5-прокси, и возвращает путь к нему. proxy_dns включён — DNS-резолв идёт
// через Tor, без утечки мимо прокси.
func WriteProxychainsConf(dir, proxyAddr string) (string, error) {
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return "", fmt.Errorf("адрес прокси %q: %w", proxyAddr, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "proxychains.conf")
	body := "# автогенерировано pentkit — весь TCP-трафик внешних тулов через SOCKS5\n" +
		"strict_chain\n" +
		"proxy_dns\n" +
		"remote_dns_subnet 224\n" +
		"tcp_read_time_out 15000\n" +
		"tcp_connect_time_out 8000\n" +
		"[ProxyList]\n" +
		"socks5 " + host + " " + port + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// userAgents — пул реалистичных User-Agent для ротации в stealth-режиме,
// чтобы запросы не выделялись одинаковой подписью клиента.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
}

// RandomUA возвращает случайный User-Agent из пула.
func RandomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

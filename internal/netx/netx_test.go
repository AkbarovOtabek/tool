package netx

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// miniSOCKS5 — минимальный SOCKS5-сервер без аутентификации для теста диалера.
// Поддерживает CONNECT с ATYP domain(3) и ipv4(1), проксирует байты как есть.
func miniSOCKS5(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func serveSOCKS(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	io.ReadFull(c, make([]byte, int(hdr[1]))) // методы
	c.Write([]byte{0x05, 0x00})               // выбираем no-auth

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(c, l)
		b := make([]byte, int(l[0]))
		io.ReadFull(c, b)
		host = string(b)
	default:
		return
	}
	p := make([]byte, 2)
	io.ReadFull(c, p)
	port := int(p[0])<<8 | int(p[1])

	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), 5*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success
	go io.Copy(target, c)
	io.Copy(c, target)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestDialerThroughSOCKS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "socks-ok host="+r.Host)
	}))
	defer srv.Close()

	socksAddr, stop := miniSOCKS5(t)
	defer stop()

	// Проверяем доступность прокси (как это делает setupOpsec перед стартом).
	if err := Check(socksAddr, 3*time.Second); err != nil {
		t.Fatalf("Check: %v", err)
	}

	client := HTTPClient(socksAddr, 8*time.Second, true)

	// 1. ATYP=ipv4: httptest слушает на 127.0.0.1 — адрес уйдёт как IP.
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET через SOCKS (ip): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "socks-ok") {
		t.Fatalf("неожиданное тело: %q", body)
	}

	// 2. ATYP=domain: подменяем host на localhost (имя), тот же порт.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	resp2, err := client.Get("https://localhost:" + port + "/")
	if err != nil {
		t.Fatalf("GET через SOCKS (domain): %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !strings.Contains(string(body2), "socks-ok") {
		t.Fatalf("неожиданное тело (domain): %q", body2)
	}
}

func TestDirectDial(t *testing.T) {
	d := NewDialer("127.0.0.1:1", 500*time.Millisecond)
	_, err := d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("ожидалась ошибка: прокси не слушает")
	}
	if !strings.Contains(err.Error(), "socks5") {
		t.Fatalf("ошибка должна быть от socks5-слоя: %v", err)
	}
}

func TestWriteProxychainsConf(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteProxychainsConf(dir, "127.0.0.1:9050")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	b := string(raw)
	if !strings.Contains(b, "socks5 127.0.0.1 9050") || !strings.Contains(b, "proxy_dns") {
		t.Fatalf("конфиг proxychains неполный:\n%s", b)
	}
}

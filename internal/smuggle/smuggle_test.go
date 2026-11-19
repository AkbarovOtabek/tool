package smuggle

import (
	"strings"
	"testing"
)

func TestHostPort(t *testing.T) {
	cases := []struct {
		in     string
		host   string
		port   string
		secure bool
		ok     bool
	}{
		{"https://bank.uz/admin", "bank.uz", "443", true, true},
		{"http://api.bank.uz:8080/x", "api.bank.uz", "8080", false, true},
		{"http://bank.uz", "bank.uz", "80", false, true},
		{"not a url", "", "", false, false},
	}
	for _, c := range cases {
		h, p, s, ok := hostPort(c.in)
		if h != c.host || p != c.port || s != c.secure || ok != c.ok {
			t.Errorf("hostPort(%q)=(%q,%q,%v,%v), want (%q,%q,%v,%v)",
				c.in, h, p, s, ok, c.host, c.port, c.secure, c.ok)
		}
	}
}

func TestRawRequestsWellFormed(t *testing.T) {
	// Запросы должны использовать CRLF и содержать оба заголовка (CL + TE).
	for name, raw := range map[string]string{"CL.TE": clteReq("h"), "TE.CL": teclReq("h")} {
		if !strings.Contains(raw, "\r\n") {
			t.Errorf("%s: нет CRLF", name)
		}
		if !strings.Contains(raw, "Content-Length:") || !strings.Contains(raw, "Transfer-Encoding: chunked") {
			t.Errorf("%s: должны быть оба заголовка CL и TE", name)
		}
		if !strings.HasPrefix(raw, "POST / HTTP/1.1\r\n") {
			t.Errorf("%s: неверная стартовая строка", name)
		}
	}
	if !strings.HasPrefix(baselineReq("h"), "GET / HTTP/1.1\r\n") {
		t.Error("baseline: неверная стартовая строка")
	}
}

func TestUniqueRoots(t *testing.T) {
	got := uniqueRoots([]string{"https://a.uz/x", "https://a.uz/y", "http://a.uz/x"})
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 корня, получено %d: %v", len(got), got)
	}
}

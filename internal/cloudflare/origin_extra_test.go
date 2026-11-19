package cloudflare

import (
	"strings"
	"testing"
)

// TestMMH3 проверяет MurmurHash3 x86_32 (seed 0) по известным векторам —
// иначе favicon-hash в Shodan будет считаться неверно и ничего не найдёт.
func TestMMH3(t *testing.T) {
	cases := map[string]int32{
		"":      0,
		"hello": 613153351,
	}
	for in, want := range cases {
		if got := mmh3_32([]byte(in)); got != want {
			t.Errorf("mmh3_32(%q) = %d, хочу %d", in, got, want)
		}
	}
}

// TestB64Mime — кодирование как Python base64.encodebytes: строки по 76 + \n.
func TestB64Mime(t *testing.T) {
	out := string(b64mime(make([]byte, 100))) // 100 байт -> ~136 символов base64
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines[0]) != 76 {
		t.Fatalf("первая строка должна быть 76 символов, получено %d", len(lines[0]))
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatal("должен быть завершающий перевод строки")
	}
}

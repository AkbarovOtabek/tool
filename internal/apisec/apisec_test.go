package apisec

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// makeHS256 собирает валидный HS256-JWT с данным секретом (для теста подбора).
func makeHS256(secret string) (signingInput, sig string) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","role":"admin"}`))
	signingInput = h + "." + p
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(signingInput))
	sig = base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	return
}

func TestCrackHS256FindsWeakSecret(t *testing.T) {
	si, sig := makeHS256("secret")
	if got := crackHS256(si, sig); got != "secret" {
		t.Fatalf("ожидался подбор секрета \"secret\", получено %q", got)
	}
}

func TestCrackHS256StrongSecretNotCracked(t *testing.T) {
	si, sig := makeHS256("fL9#aQ!z82Kx-random-strong-74plqW")
	if got := crackHS256(si, sig); got != "" {
		t.Fatalf("сильный секрет не должен подбираться, получено %q", got)
	}
}

func TestRootAndPath(t *testing.T) {
	cases := []struct{ in, root, path string }{
		{"https://bank.uz/admin/panel?x=1", "https://bank.uz", "/admin/panel?x=1"},
		{"http://api.bank.uz", "http://api.bank.uz", "/"},
		{"bad", "", ""},
	}
	for _, c := range cases {
		if r := rootOf(c.in); r != c.root {
			t.Errorf("rootOf(%q)=%q, want %q", c.in, r, c.root)
		}
		if p := pathOf(c.in); p != c.path {
			t.Errorf("pathOf(%q)=%q, want %q", c.in, p, c.path)
		}
	}
}

func TestUniqueBasesDedup(t *testing.T) {
	got := uniqueBases([]string{"https://bank.uz/a", "https://bank.uz/b", "http://bank.uz/a"})
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 базы, получено %d: %v", len(got), got)
	}
}

func TestAuthPathDetection(t *testing.T) {
	yes := []string{"https://bank.uz/login", "https://bank.uz/api/reset-password", "https://bank.uz/oauth/token", "https://bank.uz/verify-otp"}
	no := []string{"https://bank.uz/about", "https://bank.uz/products"}
	for _, u := range yes {
		if !authPathRe.MatchString(u) {
			t.Errorf("%s должен считаться auth-эндпоинтом", u)
		}
	}
	for _, u := range no {
		if authPathRe.MatchString(u) {
			t.Errorf("%s НЕ должен считаться auth-эндпоинтом", u)
		}
	}
}

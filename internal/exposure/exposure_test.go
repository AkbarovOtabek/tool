package exposure

import "testing"

func TestUniqueBasesDedupAndStripsPath(t *testing.T) {
	in := []string{
		"https://bank.uz/login",
		"https://bank.uz/account?id=1",
		"https://bank.uz", // тот же base, без пути
		"http://bank.uz/", // другая схема — отдельный base
		"not-a-url",
		"",
	}
	got := uniqueBases(in)
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 уникальных base, получено %d: %v", len(got), got)
	}
	seen := map[string]bool{}
	for _, b := range got {
		seen[b] = true
	}
	if !seen["https://bank.uz"] || !seen["http://bank.uz"] {
		t.Fatalf("неверные base: %v", got)
	}
}

// findCheck возвращает валидатор пробы по пути (для точечных проверок).
func findCheck(t *testing.T, path string) check {
	t.Helper()
	for _, c := range checks {
		if c.path == path {
			return c
		}
	}
	t.Fatalf("проба %s не найдена", path)
	return check{}
}

func TestValidatorsRejectSPAFalsePositives(t *testing.T) {
	// SPA отдаёт 200 + HTML на любой путь — находок быть не должно.
	spa := resp{status: 200, ct: "text/html; charset=utf-8", body: "<!doctype html><div id=app></div>"}
	for _, p := range []string{"/.git/config", "/.env", "/swagger.json", "/backup.sql"} {
		c := findCheck(t, p)
		if ok, _ := c.validate(spa); ok {
			t.Errorf("%s: ложное срабатывание на SPA-200/HTML", p)
		}
	}
}

func TestValidatorsConfirmRealLeaks(t *testing.T) {
	cases := []struct {
		path string
		r    resp
	}{
		{"/.git/config", resp{status: 200, ct: "text/plain", body: "[core]\n\trepositoryformatversion = 0\n"}},
		{"/.env", resp{status: 200, ct: "text/plain", body: "APP_KEY=base64:xxx\nDB_PASSWORD=secret123\n"}},
		{"/swagger.json", resp{status: 200, ct: "application/json", body: `{"openapi":"3.0.0","paths":{}}`}},
		{"/backup.sql", resp{status: 200, ct: "application/sql", body: "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);"}},
	}
	for _, tc := range cases {
		c := findCheck(t, tc.path)
		if ok, _ := c.validate(tc.r); !ok {
			t.Errorf("%s: настоящая утечка не подтверждена", tc.path)
		}
	}
}

func TestEnvNeedsTwoKeysNotOne(t *testing.T) {
	// Одна строка вида KEY= — слишком слабый сигнал, чтобы звать это .env.
	c := findCheck(t, "/.env")
	if ok, _ := c.validate(resp{status: 200, ct: "text/plain", body: "VERSION=1\n"}); ok {
		t.Error(".env: одной пары KEY= недостаточно для находки")
	}
}

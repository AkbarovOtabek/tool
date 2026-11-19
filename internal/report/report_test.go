package report

import (
	"os"
	"strings"
	"testing"

	"pentkit/internal/config"
	"pentkit/internal/store"
)

func TestGenerateIncludesChecklistAndDorks(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.Add(store.Finding{Target: "https://bank.uz", Type: store.TypeJWT, Severity: store.SevCritical,
		Title: "JWT подписан слабым секретом", Detail: "секрет: secret"})
	st.Close()

	cfg := &config.Config{}
	cfg.Engagement.Name = "test-run"
	cfg.Engagement.Client = "NBU"
	cfg.Engagement.Authorization = "Договор №1"
	cfg.Scope.Domains = []string{"nbu.uz"}

	path, err := Generate(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	htmlDoc := readFile(t, path)
	mdDoc := readFile(t, strings.TrimSuffix(path, ".html")+".md")

	for _, want := range []string{"Ручная проверка", "IDOR", "Transaction replay", "Mass assignment"} {
		if !strings.Contains(htmlDoc, want) {
			t.Errorf("HTML-отчёт не содержит чеклист-пункт %q", want)
		}
		if !strings.Contains(mdDoc, want) {
			t.Errorf("MD-отчёт не содержит чеклист-пункт %q", want)
		}
	}
	for _, want := range []string{"google.com/search", "site%3Anbu.uz", "JWT подписан слабым секретом"} {
		if !strings.Contains(htmlDoc, want) {
			t.Errorf("HTML-отчёт не содержит %q", want)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("чтение %s: %v", p, err)
	}
	return string(b)
}

package notify

import (
	"strings"
	"testing"

	"pentkit/internal/store"
)

func TestBuildMessageListsCritAndHigh(t *testing.T) {
	findings := []store.Finding{
		{Severity: store.SevCritical, Title: "JWT слабый секрет", Target: "https://bank.uz"},
		{Severity: store.SevHigh, Title: "Открыт /.git", Target: "https://bank.uz/.git"},
		{Severity: store.SevLow, Title: "Нет CSP", Target: "https://bank.uz"},
	}
	counts := map[store.Severity]int{store.SevCritical: 1, store.SevHigh: 1, store.SevLow: 1}
	msg := buildMessage("acme", findings, counts)

	if !strings.Contains(msg, "acme") {
		t.Error("нет имени работы")
	}
	if !strings.Contains(msg, "JWT слабый секрет") || !strings.Contains(msg, "Открыт /.git") {
		t.Error("крит/high находки не попали в сводку")
	}
	if strings.Contains(msg, "Нет CSP") {
		t.Error("low-находка не должна попадать в сводку")
	}
}

func TestBuildMessageNoFindings(t *testing.T) {
	msg := buildMessage("x", nil, map[store.Severity]int{})
	if !strings.Contains(msg, "нет") {
		t.Error("ожидалось сообщение об отсутствии крит/high")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("abcdef", 3) != "abc…" {
		t.Error("truncate работает неверно")
	}
	if truncate("ab", 5) != "ab" {
		t.Error("короткую строку не трогаем")
	}
}

package secrets

import "testing"

// TestRulesMatch проверяет, что сигнатуры ловят известные образцы ключей и не
// срабатывают на безобидном коде (защита от деградации regex при правках).
func TestRulesMatch(t *testing.T) {
	// Образцы собираем из кусков: литеральный «ключ» не попадает в исходник и
	// не триггерит secret-scanning GitHub. Ключи всё равно фейковые, а regex
	// проверяется на собранной во время теста непрерывной строке.
	hits := map[string]string{
		"AWS Access Key":    "AKIA" + "IOSFODNN7EXAMPLE",
		"Google API Key":    "AIza" + "SyB1234567890abcdefghijklmnopqrstuv",
		"Slack Token":       "xoxb-" + "123456789012-abcdefghijklmnop",
		"GitHub Token":      "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz",
		"Private Key Block": "-----BEGIN RSA PRIVATE KEY-----",
		"JWT":               "eyJhbGciOiJIUzI1Ni9" + ".eyJzdWIiOiIxMjM0NTY3ODk0" + ".SflKxwRJSMeKKF2QT4",
	}
	for name, sample := range hits {
		var matched bool
		for _, rl := range rules {
			if rl.name == name && rl.re.MatchString(sample) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("правило %q не поймало образец: %s", name, sample)
		}
	}

	benign := `function add(a, b) { return a + b; } // just some code 12345`
	for _, rl := range rules {
		if rl.name == "Generic Secret" || rl.name == "JWT" {
			continue // generic/JWT специально широкие — проверяем отдельно
		}
		if rl.re.MatchString(benign) {
			t.Errorf("правило %q ложно сработало на безобидном коде", rl.name)
		}
	}
}

func TestRedact(t *testing.T) {
	in := "AKIA" + "IOSFODNN7EXAMPLE"
	out := redact(in)
	if out == in {
		t.Fatal("redact не скрыл секрет")
	}
	if len(out) >= len(in) {
		t.Fatalf("redact должен укорачивать: %q", out)
	}
}

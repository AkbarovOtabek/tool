package setup

import (
	"os"
	"strings"
	"testing"
)

func TestRegistryBinsUniqueAndValid(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range registry {
		if tl.bin == "" {
			t.Error("пустое имя bin в реестре")
		}
		if seen[tl.bin] {
			t.Errorf("дубль bin в реестре: %s", tl.bin)
		}
		seen[tl.bin] = true
		if len(tl.steps) == 0 {
			t.Errorf("%s: нет шагов установки", tl.bin)
		}
		for _, s := range tl.steps {
			switch s.kind {
			case kindApt, kindGo, kindPipx, kindSh:
			default:
				t.Errorf("%s: неизвестный вид шага %q", tl.bin, s.kind)
			}
			if s.arg == "" {
				t.Errorf("%s: пустой аргумент шага", tl.bin)
			}
		}
	}
}

// TestKeyToolsCovered — ключевые тулы, которые ищет код, должны быть в реестре.
func TestKeyToolsCovered(t *testing.T) {
	want := []string{"nuclei", "httpx", "subfinder", "ffuf", "katana", "nmap",
		"sqlmap", "kr", "jwt_tool", "dalfox", "gau", "gf", "wafw00f", "theharvester"}
	have := map[string]bool{}
	for _, tl := range registry {
		have[tl.bin] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("ключевой тул %q отсутствует в реестре установки", w)
		}
	}
}

func TestEnsurePathAddsGobin(t *testing.T) {
	old := os.Getenv("PATH")
	defer os.Setenv("PATH", old)
	os.Setenv("PATH", "/usr/bin")
	ensurePath()
	p := os.Getenv("PATH")
	if !strings.Contains(p, "/usr/bin") {
		t.Error("ensurePath потерял исходный PATH")
	}
	// должен добавить хотя бы один bin-каталог (go bin или ~/.local/bin)
	if p == "/usr/bin" {
		t.Error("ensurePath ничего не добавил в PATH")
	}
}

func TestKeysSorted(t *testing.T) {
	got := keys(map[string]bool{"c": true, "a": true, "b": true})
	if strings.Join(got, ",") != "a,b,c" {
		t.Errorf("keys не отсортированы: %v", got)
	}
}

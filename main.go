// pentkit — оркестратор для авторизованного пентеста со встроенным веб-интерфейсом.
// Пайплайн: recon -> cloudflare -> crawl -> vuln -> web -> extra -> report.
//
// Инструмент только для систем, на тест которых есть письменное разрешение.
// Scope и авторизация обязательны; все цели фильтруются по scope.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/engine"
	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/report"
	"pentkit/internal/runner"
	"pentkit/internal/scope"
	"pentkit/internal/setup"
	"pentkit/internal/store"
	"pentkit/internal/ui"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "run":
		cmdPipeline(os.Args[2:], engineOpts("run", false), true) // run: доустановка тулов по умолчанию
	case "recon":
		cmdPipeline(os.Args[2:], engineOpts("recon", false), false)
	case "scan":
		cmdPipeline(os.Args[2:], engineOpts("scan", false), false)
	case "web":
		cmdPipeline(os.Args[2:], engineOpts("web", false), false)
	case "report":
		cmdReport(os.Args[2:])
	case "setup", "install":
		cmdSetup(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("pentkit", version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`pentkit ` + version + ` — оркестратор авторизованного пентеста

Использование:
  pentkit serve [-addr 127.0.0.1:8777]     Веб-интерфейс (всё в браузере)
  pentkit setup                            Доустановить недостающие тулы (apt/go/pipx/git)
  pentkit run    -c config.yaml [-v] [--no-verify]   Полный пайплайн (сам доустанавливает тулы)
  pentkit recon  -c config.yaml            Только разведка + поиск origin за CF
  pentkit scan   -c config.yaml            Уязвимости: nuclei + takeover + TLS + nikto
  pentkit web    -c config.yaml            Краулинг + веб-тесты + секреты (ffuf/ferox/dalfox/gf)
  pentkit report -c config.yaml            Пересобрать отчёт из находок
  pentkit version

Флаги:
  -c   путь к конфигу (по умолчанию config.yaml)
  -v   подробный вывод
  --no-verify  не перепроверять срабатывания nuclei (быстрее, больше ложных)
  --install    доустановить недостающие тулы перед запуском (для run включено по умолчанию)
  --no-install для run: НЕ доустанавливать тулы
  --sqli       активные SQL-инъекции (sqlmap + nuclei -dast) — агрессивно, по согласованию
  --passive    пассивный режим: без портскана/nikto/активных проверок (тихо для WAF)

Скрытность (в config.yaml):
  tor: true                 весь трафик через локальный Tor (нужен сервис tor + proxychains4)
  proxy: socks5://host:port свой SOCKS5 вместо Tor
  stealth: true             тихий режим: низкий rate/concurrency, джиттер, ротация User-Agent

Самый простой старт — веб-интерфейс:
  ./pentkit serve
  затем открой показанную ссылку в браузере.
`)
}

func engineOpts(stage string, noVerify bool) engine.Options {
	switch stage {
	case "run":
		o := engine.AllOn()
		o.Verify = !noVerify
		return o
	case "recon":
		return engine.Options{Cloudflare: true, Fingerprint: true, OSINT: true}
	case "scan":
		return engine.Options{Vuln: true, Exposure: true, Bypass: true, Takeover: true, TLS: true, Nikto: true,
			WordPress: true, Nmap: true, Exploit: true, MsfCheck: true, Verify: !noVerify}
	case "web":
		return engine.Options{Crawl: true, Fingerprint: true, Web: true, Secrets: true,
			Exposure: true, JWT: true, APIDisco: true, Bypass: true}
	}
	return engine.AllOn()
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8777", "адрес веб-интерфейса")
	_ = fs.Parse(args)
	if err := ui.Serve(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка веб-сервера:", err)
		os.Exit(1)
	}
}

func cmdPipeline(args []string, baseStage engine.Options, defaultInstall bool) {
	fs := flag.NewFlagSet("pentkit", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "путь к конфигу")
	verbose := fs.Bool("v", false, "подробный вывод")
	noVerify := fs.Bool("no-verify", false, "не перепроверять срабатывания nuclei")
	sqli := fs.Bool("sqli", false, "включить активные SQL-инъекции (sqlmap + nuclei -dast)")
	passive := fs.Bool("passive", false, "пассивный режим: без шумных активных проверок (для WAF/Firewall)")
	install := fs.Bool("install", defaultInstall, "перед запуском доустановить недостающие тулы (apt/go/pipx; apt требует root/sudo)")
	noInstall := fs.Bool("no-install", false, "не доустанавливать тулы (отменяет -install, в т.ч. дефолт для run)")
	_ = fs.Parse(args)
	doInstall := *install && !*noInstall

	cfg, sc, st := load(*cfgPath)
	defer st.Close()

	// Учитываем --no-verify для профилей, где есть перепроверка.
	opts := baseStage
	if *noVerify {
		opts.Verify = false
	}
	if *sqli {
		opts.Web = true
		opts.SQLi = true
	}
	if *passive {
		// Пассив важнее любого агрессивного флага: оставляем только тихие модули.
		opts = engine.Options{Cloudflare: true, Fingerprint: true, OSINT: true}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	rn := runner.New(cfg.Timeout.Duration, *verbose)
	rn.Passive = *passive
	// Автоустановка тулов — до opsec (без proxychains) и до пайплайна.
	if doInstall {
		setup.Install(ctx, rn, event.Console{})
	}
	engDir := filepath.Join(cfg.OutputDir, cfg.Engagement.Name)
	setupOpsec(cfg, rn, engDir)
	start := time.Now()
	path, err := engine.Run(ctx, cfg, sc, rn, st, event.Console{}, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка пайплайна:", err)
	}
	summary(st, path)
	fmt.Printf("\nГотово за %s\n", time.Since(start).Round(time.Second))
}

// cmdSetup доустанавливает все недостающие внешние тулы (apt/go/pipx/git).
func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	verbose := fs.Bool("v", false, "подробный вывод")
	_ = fs.Parse(args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	rn := runner.New(15*time.Minute, *verbose)
	sum := setup.Install(ctx, rn, event.Console{})
	fmt.Printf("\nУстановлено: %d · уже было: %d · не удалось: %d\n",
		len(sum.Installed), len(sum.Already), len(sum.Failed))
	if len(sum.Failed) > 0 {
		fmt.Println("Не поставлены (см. README):", strings.Join(sum.Failed, ", "))
		os.Exit(1)
	}
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "путь к конфигу")
	_ = fs.Parse(args)
	cfg, _, st := load(*cfgPath)
	defer st.Close()
	path, err := report.Generate(cfg, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка отчёта:", err)
		os.Exit(1)
	}
	summary(st, path)
}

func load(cfgPath string) (*config.Config, *scope.Scope, *store.Store) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка конфига:", err)
		os.Exit(1)
	}
	sc, err := scope.Compile(cfg.Scope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка scope:", err)
		os.Exit(1)
	}
	engDir := filepath.Join(cfg.OutputDir, cfg.Engagement.Name)
	st, err := store.Open(engDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка хранилища:", err)
		os.Exit(1)
	}
	fmt.Printf("=== pentkit %s | работа: %s | клиент: %s ===\n", version, cfg.Engagement.Name, cfg.Engagement.Client)
	fmt.Printf("    авторизация: %s\n", cfg.Engagement.Authorization)
	fmt.Printf("    результаты: %s\n", engDir)
	return cfg, sc, st
}

// setupOpsec применяет к runner режим скрытности из конфига: SOCKS5/Tor (через
// proxychains4 для внешних тулов и SOCKS для Go-клиентов) и stealth. Падает
// заранее с понятной ошибкой, если прокси недоступен или нет proxychains4.
func setupOpsec(cfg *config.Config, rn *runner.Runner, engDir string) {
	rn.Stealth = cfg.Stealth
	if addr, on := cfg.SOCKS(); on {
		if err := netx.Check(addr, 5*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка прокси/Tor: %v\n"+
				"   Запусти сервис tor (sudo systemctl start tor; ss -lnt | grep 9050)\n"+
				"   или задай рабочий proxy: socks5://host:port в конфиге.\n", err)
			os.Exit(1)
		}
		if !rn.Has("proxychains4") {
			fmt.Fprintln(os.Stderr, "Ошибка: включён tor/proxy, но внешним тулам нужен proxychains4 (apt install proxychains4)")
			os.Exit(1)
		}
		conf, err := netx.WriteProxychainsConf(engDir, addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Ошибка proxychains.conf:", err)
			os.Exit(1)
		}
		rn.UseProxychains(conf, addr)
		fmt.Printf("    🔒 трафик через SOCKS5 %s (proxychains4 для тулов + Go-SOCKS)\n", addr)
		fmt.Println("    ⚠ raw-скан (naabu/nmap) переведён в connect-режим; DNS через Tor")
	}
	if rn.Passive {
		fmt.Println("    🛡 пассивный режим: без портскана/nikto/wafw00f/активных инъекций")
	}
	if cfg.Stealth {
		fmt.Printf("    🐢 stealth: rate=%d/s, concurrency=%d, джиттер, ротация User-Agent\n", cfg.RateLimit, cfg.Concurrency)
	}
}

func summary(st *store.Store, reportPath string) {
	c := st.Counts()
	fmt.Printf("  находок: crit=%d high=%d med=%d low=%d info=%d\n",
		c[store.SevCritical], c[store.SevHigh], c[store.SevMedium], c[store.SevLow], c[store.SevInfo])
	if reportPath != "" {
		fmt.Println("  отчёт:", reportPath)
	}
}

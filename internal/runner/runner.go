// Package runner запускает внешние тулы Kali (subfinder, nuclei, httpx, ...).
// Отвечает за таймауты, проверку наличия тула, стриминг вывода и лог команд.
package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner — обёртка над exec с общими настройками.
type Runner struct {
	Timeout time.Duration
	Verbose bool
	// SOCKS — адрес SOCKS5-прокси (host:port) для Go-клиентов модулей ("" = напрямую).
	SOCKS string
	// Stealth — тихий режим: модули выставляют щадящие флаги тулов (rate/delay/UA).
	Stealth bool
	// Passive — пассивный режим: модули пропускают шумные/активные шаги (portscan, nikto, ...).
	Passive bool
	// proxyConf — путь к proxychains.conf; если задан, внешние тулы идут через proxychains4.
	proxyConf string
	logMu     sync.Mutex
	// present кэширует наличие тулов, чтобы не дёргать LookPath постоянно.
	present sync.Map
}

// UseProxychains включает запуск всех внешних тулов через proxychains4 с
// указанным конфигом и задаёт SOCKS-адрес для Go-клиентов модулей.
func (r *Runner) UseProxychains(confPath, socksAddr string) {
	r.proxyConf = confPath
	r.SOCKS = socksAddr
}

// Proxied сообщает, активен ли режим прокси (модули переводят raw-тулы в connect-режим).
func (r *Runner) Proxied() bool { return r.SOCKS != "" }

// Stealthy сообщает, включён ли тихий режим.
func (r *Runner) Stealthy() bool { return r.Stealth }

// command строит exec.Cmd, при включённом proxychains оборачивая тул в proxychains4.
func (r *Runner) command(ctx context.Context, tool string, args []string) *exec.Cmd {
	if r.proxyConf != "" {
		full := append([]string{"-q", "-f", r.proxyConf, tool}, args...)
		return exec.CommandContext(ctx, "proxychains4", full...)
	}
	return exec.CommandContext(ctx, tool, args...)
}

// New создаёт runner.
func New(timeout time.Duration, verbose bool) *Runner {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	return &Runner{Timeout: timeout, Verbose: verbose}
}

// Has проверяет, установлен ли тул (есть в PATH).
func (r *Runner) Has(tool string) bool {
	if v, ok := r.present.Load(tool); ok {
		return v.(bool)
	}
	_, err := exec.LookPath(tool)
	ok := err == nil
	r.present.Store(tool, ok)
	return ok
}

// Result — результат запуска.
type Result struct {
	Lines    []string // stdout по строкам (без пустых)
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Run запускает тул и собирает stdout целиком.
func (r *Runner) Run(ctx context.Context, tool string, args ...string) Result {
	if !r.Has(tool) {
		return Result{Err: fmt.Errorf("тул %q не найден в PATH (см. README: установка тулов)", tool)}
	}
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	r.logCmd(tool, args)
	cmd := r.command(cctx, tool, args)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	res := Result{Stdout: out.String(), Stderr: errb.String(), Err: err}
	if cctx.Err() == context.DeadlineExceeded {
		res.Err = fmt.Errorf("%s: превышен таймаут %s", tool, r.Timeout)
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			res.Lines = append(res.Lines, line)
		}
	}
	return res
}

// RunStdin запускает тул, подавая data на stdin (например, httpx читает список хостов).
func (r *Runner) RunStdin(ctx context.Context, stdin string, tool string, args ...string) Result {
	if !r.Has(tool) {
		return Result{Err: fmt.Errorf("тул %q не найден в PATH", tool)}
	}
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	r.logCmd(tool, args)
	cmd := r.command(cctx, tool, args)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	res := Result{Stdout: out.String(), Stderr: errb.String(), Err: err}
	if cctx.Err() == context.DeadlineExceeded {
		res.Err = fmt.Errorf("%s: превышен таймаут %s", tool, r.Timeout)
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			res.Lines = append(res.Lines, line)
		}
	}
	return res
}

func (r *Runner) logCmd(tool string, args []string) {
	if !r.Verbose {
		return
	}
	r.logMu.Lock()
	defer r.logMu.Unlock()
	prefix := ""
	if r.proxyConf != "" {
		prefix = "proxychains4 → "
	}
	fmt.Printf("  ▸ %s%s %s\n", prefix, tool, strings.Join(args, " "))
}

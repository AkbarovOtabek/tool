// Package event — общий канал прогресса для пайплайна. Модули пишут лог и смену
// этапов через Sink; CLI печатает в консоль, веб-UI копит в буфер для опроса.
package event

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sink принимает события от модулей сканирования.
type Sink interface {
	Logf(format string, a ...any)
	Logln(a ...any)
	Stage(name string)
}

// Console печатает события в stdout (для CLI).
type Console struct{}

func (Console) Logf(f string, a ...any) { fmt.Printf(f, a...) }
func (Console) Logln(a ...any)          { fmt.Println(a...) }
func (Console) Stage(name string)       { fmt.Printf("\n== %s ==\n", name) }

// Buffered копит строки лога и текущий этап для веб-UI (опрос через /api/status).
type Buffered struct {
	mu      sync.Mutex
	lines   []string
	stage   string
	running bool
	started time.Time
}

// NewBuffered создаёт буферный sink.
func NewBuffered() *Buffered { return &Buffered{} }

func (b *Buffered) push(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.lines = append(b.lines, ts+"  "+line)
	}
	// Ограничиваем буфер, чтобы не рос бесконечно.
	if len(b.lines) > 5000 {
		b.lines = b.lines[len(b.lines)-5000:]
	}
}

func (b *Buffered) Logf(f string, a ...any) { b.push(strings.TrimRight(fmt.Sprintf(f, a...), "\n")) }
func (b *Buffered) Logln(a ...any)          { b.push(strings.TrimRight(fmt.Sprintln(a...), "\n")) }

func (b *Buffered) Stage(name string) {
	b.mu.Lock()
	b.stage = name
	b.mu.Unlock()
	b.push("== " + name + " ==")
}

// Start/Finish помечают жизненный цикл работы.
func (b *Buffered) Start() {
	b.mu.Lock()
	b.running = true
	b.started = time.Now()
	b.lines = nil
	b.stage = "старт"
	b.mu.Unlock()
}

func (b *Buffered) Finish() {
	b.mu.Lock()
	b.running = false
	b.stage = "готово"
	b.mu.Unlock()
}

// Snapshot возвращает текущее состояние для UI.
func (b *Buffered) Snapshot() (stage string, running bool, lines []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]string, len(b.lines))
	copy(cp, b.lines)
	return b.stage, b.running, cp
}

// Running сообщает, идёт ли работа.
func (b *Buffered) Running() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.running
}

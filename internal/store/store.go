// Package store хранит находки движка в едином виде (JSONL на диск + индекс в памяти).
// Все модули (recon, cloudflare, vuln, web) пишут сюда, а report читает отсюда.
package store

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity — уровень важности находки.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// sevRank — для сортировки по убыванию важности.
var sevRank = map[Severity]int{
	SevCritical: 5, SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1,
}

// Тип находки.
const (
	TypeSubdomain  = "subdomain"
	TypeDNS        = "dns"
	TypePort       = "port"
	TypeHTTP       = "http"
	TypeTech       = "tech"
	TypeCloudflare = "cloudflare"
	TypeOrigin     = "origin"
	TypeVuln       = "vuln"
	TypeDir        = "dir"
	TypeParam      = "param"
	TypeInjection  = "injection"
	TypeWAF        = "waf"      // обнаруженный WAF/фаервол
	TypeOSINT      = "osint"    // почты/хосты из открытых источников
	TypeHeader     = "header"   // анализ security-заголовков (пассивно)
	TypeSecret     = "secret"   // утечка ключа/токена в JS/ответах
	TypeCORS       = "cors"     // мисконфигурация CORS
)

// Finding — одна находка. ID считается детерминированно, чтобы автоматически дедуплицировать.
type Finding struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`         // к какому хосту/URL относится
	Type      string    `json:"type"`           // см. константы Type*
	Severity  Severity  `json:"severity"`       // info..critical
	Title     string    `json:"title"`          // короткое описание
	Detail    string    `json:"detail,omitempty"`
	Evidence  string    `json:"evidence,omitempty"` // доказательство (вывод тула, запрос/ответ)
	Tool      string    `json:"tool,omitempty"`     // чем найдено
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func makeID(f Finding) string {
	h := sha1.Sum([]byte(strings.ToLower(f.Type + "|" + f.Target + "|" + f.Title)))
	return hex.EncodeToString(h[:])[:16]
}

// Store — потокобезопасное хранилище на одну работу (engagement).
type Store struct {
	mu    sync.Mutex
	dir   string
	file  *os.File
	w     *bufio.Writer
	byID  map[string]Finding
	order []string

	// Инкрементальные индексы — чтобы не пересобирать всё при каждом опросе UI.
	counts  map[Severity]int    // счётчики по важности (O(1))
	typeIdx map[string][]string // тип -> id находок
	cache   []Finding           // отсортированный срез All(); пересобирается лениво
	dirty   bool                // cache устарел
	unflush int                 // записей в bufio без flush (батчим syscall'ы)
}

// flushEvery — порог батч-flush: при разведке находки летят тысячами, flush на
// каждую — это syscall на запись. All()/Counts() читают из памяти, а файл нужен
// только для дедупа при повторном запуске, поэтому небольшая задержка безопасна.
const flushEvery = 64

// Open открывает (создаёт) хранилище в каталоге работы.
func Open(engagementDir string) (*Store, error) {
	if err := os.MkdirAll(engagementDir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(engagementDir, "findings.jsonl")
	s := &Store{dir: engagementDir, byID: map[string]Finding{},
		counts: map[Severity]int{}, typeIdx: map[string][]string{}, dirty: true}
	// Подгружаем уже существующие находки (чтобы повторный запуск не плодил дубли).
	if data, err := os.ReadFile(path); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var f Finding
			if json.Unmarshal([]byte(line), &f) == nil {
				if _, ok := s.byID[f.ID]; !ok {
					s.order = append(s.order, f.ID)
					s.counts[f.Severity]++
					s.typeIdx[f.Type] = append(s.typeIdx[f.Type], f.ID)
				}
				s.byID[f.ID] = f
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	s.file = f
	s.w = bufio.NewWriter(f)
	return s, nil
}

// Add добавляет находку. Дубли (по детерминированному ID) игнорируются.
// Возвращает true, если находка новая.
func (s *Store) Add(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	if f.Severity == "" {
		f.Severity = SevInfo
	}
	f.ID = makeID(f)
	if _, exists := s.byID[f.ID]; exists {
		return false
	}
	s.byID[f.ID] = f
	s.order = append(s.order, f.ID)
	s.counts[f.Severity]++
	s.typeIdx[f.Type] = append(s.typeIdx[f.Type], f.ID)
	s.dirty = true
	if b, err := json.Marshal(f); err == nil {
		s.w.Write(b)
		s.w.WriteByte('\n')
		if s.unflush++; s.unflush >= flushEvery {
			s.w.Flush()
			s.unflush = 0
		}
	}
	return true
}

// All возвращает все находки, отсортированные по важности (убывание), затем по типу.
// Результат кэшируется и пересобирается только после новых находок — частые
// опросы UI не платят за повторную сортировку.
func (s *Store) All() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty && s.cache != nil {
		return s.cache
	}
	out := make([]Finding, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] > sevRank[out[j].Severity]
		}
		return out[i].Type < out[j].Type
	})
	s.cache = out
	s.dirty = false
	return out
}

// ByType возвращает находки одного типа (через индекс, без полной сортировки).
func (s *Store) ByType(t string) []Finding {
	s.mu.Lock()
	ids := s.typeIdx[t]
	out := make([]Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.byID[id])
	}
	s.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank[out[i].Severity] > sevRank[out[j].Severity]
	})
	return out
}

// Counts — сводка по важности (O(1), инкрементальные счётчики).
func (s *Store) Counts() map[Severity]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := make(map[Severity]int, len(s.counts))
	for k, v := range s.counts {
		c[k] = v
	}
	return c
}

// Dir возвращает каталог работы.
func (s *Store) Dir() string { return s.dir }

// Close закрывает файл хранилища.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w != nil {
		s.w.Flush()
	}
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// String — удобный вывод находки в лог.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s %s — %s", strings.ToUpper(string(f.Severity)), f.Type, f.Target, f.Title)
}

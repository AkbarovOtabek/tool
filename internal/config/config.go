// Package config загружает YAML-конфиг движка: scope работы, ключи API, пути, лимиты.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config — корневая конфигурация.
type Config struct {
	// Engagement — метаданные текущей работы (клиент, идентификатор, авторизация).
	Engagement Engagement `yaml:"engagement"`
	// Scope — что можно трогать, что нельзя.
	Scope Scope `yaml:"scope"`
	// Concurrency — сколько целей обрабатывать параллельно.
	Concurrency int `yaml:"concurrency"`
	// RateLimit — глобальный предел запросов в секунду для сетевых тулов (0 = без лимита).
	RateLimit int `yaml:"rate_limit"`
	// Tor маршрутизирует весь трафик через локальный Tor (SOCKS5 127.0.0.1:9050).
	// Нужен запущенный сервис tor (не Tor Browser) и proxychains4 для внешних тулов.
	Tor bool `yaml:"tor"`
	// Proxy — произвольный SOCKS5-прокси (socks5://host:port). Переопределяет Tor.
	Proxy string `yaml:"proxy"`
	// Stealth включает тихий режим уклонения от WAF/Firewall: низкий rate/concurrency,
	// джиттер, ротация User-Agent, щадящие флаги тулов (меньше риск попасть в блок-лист).
	Stealth bool `yaml:"stealth"`
	// Timeout — таймаут одного внешнего тула (например, "15m").
	Timeout Duration `yaml:"timeout"`
	// OutputDir — куда складывать результаты работ.
	OutputDir string `yaml:"output_dir"`
	// Keys — ключи внешних сервисов (для origin discovery и обогащения).
	Keys Keys `yaml:"keys"`
	// Wordlists — пути к словарям на Kali.
	Wordlists Wordlists `yaml:"wordlists"`
}

// SOCKS возвращает адрес SOCKS5-прокси (host:port) и флаг, включён ли он.
// Приоритет: явный proxy; иначе tor:true -> 127.0.0.1:9050.
func (c *Config) SOCKS() (string, bool) {
	if c.Proxy != "" {
		return stripScheme(c.Proxy), true
	}
	if c.Tor {
		return "127.0.0.1:9050", true
	}
	return "", false
}

func stripScheme(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "socks5h://")
	p = strings.TrimPrefix(p, "socks5://")
	return strings.TrimSuffix(p, "/")
}

// Duration — обёртка над time.Duration, чтобы YAML принимал строки вида "15m".
type Duration struct{ time.Duration }

// UnmarshalYAML разбирает строку длительности (time.ParseDuration).
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("неверный формат длительности %q (пример: 15m): %w", s, err)
	}
	d.Duration = dur
	return nil
}

// Engagement описывает работу и подтверждает авторизацию.
type Engagement struct {
	Name          string `yaml:"name"`          // короткий идентификатор (папка результатов)
	Client        string `yaml:"client"`        // название организации
	Authorization string `yaml:"authorization"` // ссылка/номер разрешения на тест
}

// Scope задаёт границы теста.
type Scope struct {
	Domains    []string `yaml:"domains"`      // корневые домены в скоупе
	CIDRs      []string `yaml:"cidrs"`        // диапазоны IP в скоупе
	OutOfScope []string `yaml:"out_of_scope"` // хосты/домены вне скоупа (исключения)
}

// Keys — ключи внешних API.
type Keys struct {
	Shodan         string `yaml:"shodan"`
	SecurityTrails string `yaml:"securitytrails"`
	Censys         string `yaml:"censys"` // формат "id:secret"
	LeakIX         string `yaml:"leakix"` // ключ leakix.net (утёкшие сервисы/конфиги)
	IntelX         string `yaml:"intelx"` // ключ intelx.io (утёкшие данные/credentials)
}

// Wordlists — пути к словарям (значения по умолчанию под Kali).
type Wordlists struct {
	Dirs   string `yaml:"dirs"`
	Subs   string `yaml:"subs"`
	Params string `yaml:"params"`
}

// Default возвращает конфиг со значениями по умолчанию для Kali.
func Default() *Config {
	return &Config{
		Concurrency: 10,
		RateLimit:   0,
		Timeout:     Duration{15 * time.Minute},
		OutputDir:   "engagements",
		Wordlists: Wordlists{
			Dirs:   "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
			Subs:   "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
			Params: "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
		},
	}
}

// Load читает конфиг из файла, накладывая его поверх значений по умолчанию.
func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("читаю конфиг: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("разбираю YAML: %w", err)
	}
	if cfg.Engagement.Name == "" {
		return nil, fmt.Errorf("engagement.name обязателен (идентификатор работы)")
	}
	if cfg.Engagement.Authorization == "" {
		return nil, fmt.Errorf("engagement.authorization обязателен: укажи номер/ссылку разрешения на тест")
	}
	if len(cfg.Scope.Domains) == 0 && len(cfg.Scope.CIDRs) == 0 {
		return nil, fmt.Errorf("scope пуст: укажи хотя бы один домен или CIDR")
	}
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if addr, on := cfg.SOCKS(); on {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("неверный proxy %q (ожидается host:port или socks5://host:port): %w", cfg.Proxy, err)
		}
	}
	// Stealth: консервативные пределы, чтобы не словить блокировку WAF/Firewall.
	if cfg.Stealth {
		if cfg.RateLimit == 0 {
			cfg.RateLimit = 10
		}
		if cfg.Concurrency > 3 {
			cfg.Concurrency = 3
		}
	}
	return cfg, nil
}

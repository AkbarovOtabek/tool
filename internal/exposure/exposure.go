// Package exposure — точечный поиск опасных «утечек поверхности»: открытых
// служебных файлов и интерфейсов, которые часто остаются доступными даже на
// хорошо защищённой инфраструктуре и дают реальный impact:
//
//   - раскрытый VCS (.git/.svn) → утечка исходников;
//   - .env и бэкапы (*.sql/*.zip/*.bak) → креды и дампы БД;
//   - Spring Boot /actuator/env, Apache /server-status, phpinfo → секреты/инфо;
//   - Swagger/OpenAPI и GraphQL-интроспекция → карта API для дальнейших атак;
//   - .htpasswd/.git-credentials/.DS_Store → креды и структура каталогов.
//
// В отличие от сырого брутфорса каталогов, каждый пробник ВАЛИДИРУЕТ тело ответа
// по сигнатуре — иначе SPA с catch-all 200 завалила бы отчёт ложными находками.
// Модуль самодостаточный (свой HTTP-клиент, умеет через Tor/SOCKS) и уважает
// пассивный режим: активные пробы в нём не шлются.
package exposure

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"pentkit/internal/event"
	"pentkit/internal/netx"
	"pentkit/internal/runner"
	"pentkit/internal/store"
)

const (
	maxHosts  = 30               // по скольким базовым URL гоняем пробники
	maxRead   = 128 * 1024       // читаем не больше 128 КБ тела на пробу
	fetchPool = 10               // параллельных запросов
	reqTO     = 12 * time.Second // таймаут одной пробы
)

// resp — минимальный результат пробы.
type resp struct {
	status int
	ct     string // Content-Type (lower)
	length int64  // Content-Length (-1 если неизвестно)
	body   string // префикс тела (до maxRead)
}

// check — один пробник. validate возвращает (подтверждено, деталь для отчёта).
type check struct {
	path     string
	method   string // "" => GET
	reqBody  string // тело для POST (например, GraphQL-интроспекция)
	ctype    string // Content-Type запроса
	sev      store.Severity
	title    string
	tags     []string
	validate func(r resp) (bool, string)
}

var (
	reEnv       = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`)
	reGitConfig = regexp.MustCompile(`(?s)\[core\].*repositoryformatversion`)
)

// checks — курированный набор высокоценных проб. Порядок не важен (дедуп в store).
var checks = []check{
	{path: "/.git/config", sev: store.SevHigh, tags: []string{"vcs-exposure", "source-leak"},
		title: "Открыт /.git/config — утечка Git-репозитория (исходники)",
		validate: func(r resp) (bool, string) {
			if r.status == 200 && reGitConfig.MatchString(r.body) {
				return true, "дамп исходников: git-dumper " + "<host>/.git/"
			}
			return false, ""
		}},
	{path: "/.git/HEAD", sev: store.SevHigh, tags: []string{"vcs-exposure", "source-leak"},
		title: "Открыт /.git/HEAD — доступен Git-репозиторий",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.HasPrefix(strings.TrimSpace(r.body), "ref:"), ""
		}},
	{path: "/.svn/entries", sev: store.SevHigh, tags: []string{"vcs-exposure", "source-leak"},
		title: "Открыт /.svn — утечка SVN-репозитория",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && (strings.Contains(r.body, "svn://") || strings.Contains(r.body, "dir\n") || strings.Contains(r.body, "has-props")), ""
		}},
	{path: "/.env", sev: store.SevHigh, tags: []string{"config-leak", "secret-leak"},
		title: "Открыт /.env — конфиг приложения с кредами",
		validate: func(r resp) (bool, string) {
			if r.status == 200 && !strings.Contains(r.ct, "html") && len(reEnv.FindAllString(r.body, 3)) >= 2 {
				return true, "внутри обычно DB_PASSWORD/APP_KEY/SECRET — сменить немедленно"
			}
			return false, ""
		}},
	{path: "/.env.production", sev: store.SevHigh, tags: []string{"config-leak", "secret-leak"},
		title: "Открыт /.env.production — прод-конфиг с кредами",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && !strings.Contains(r.ct, "html") && len(reEnv.FindAllString(r.body, 3)) >= 2, ""
		}},
	{path: "/.git-credentials", sev: store.SevHigh, tags: []string{"secret-leak"},
		title: "Открыт /.git-credentials — логины/пароли к Git",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "://") && strings.Contains(r.body, "@"), ""
		}},
	{path: "/.htpasswd", sev: store.SevHigh, tags: []string{"secret-leak"},
		title: "Открыт /.htpasswd — хэши паролей basic-auth",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && !strings.Contains(r.ct, "html") && strings.Contains(r.body, ":") && (strings.Contains(r.body, "$apr1$") || strings.Contains(r.body, "$2y$") || regexp.MustCompile(`^[\w.-]+:\S+`).MatchString(strings.TrimSpace(r.body))), ""
		}},
	{path: "/actuator", sev: store.SevMedium, tags: []string{"spring-actuator", "info-disclosure"},
		title: "Открыт Spring Boot /actuator — служебные эндпоинты",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.ct, "json") && strings.Contains(r.body, "_links"), "проверь /actuator/env, /heapdump, /actuator/httptrace"
		}},
	{path: "/actuator/env", sev: store.SevHigh, tags: []string{"spring-actuator", "secret-leak"},
		title: "Открыт /actuator/env — переменные окружения (часто с секретами)",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.ct, "json") && (strings.Contains(r.body, "propertySources") || strings.Contains(r.body, "systemEnvironment")), ""
		}},
	{path: "/actuator/heapdump", sev: store.SevHigh, tags: []string{"spring-actuator", "memory-leak"},
		title: "Открыт /actuator/heapdump — дамп памяти JVM",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && (strings.Contains(r.ct, "octet-stream") || r.length > 1_000_000), "в дампе — токены/сессии в открытом виде"
		}},
	{path: "/server-status", sev: store.SevMedium, tags: []string{"info-disclosure"},
		title: "Открыт Apache /server-status — запросы и внутренние адреса",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "Apache Server Status"), ""
		}},
	{path: "/phpinfo.php", sev: store.SevMedium, tags: []string{"info-disclosure"},
		title:    "Открыт phpinfo() — полная конфигурация PHP/окружения",
		validate: validatePHPInfo},
	{path: "/info.php", sev: store.SevMedium, tags: []string{"info-disclosure"},
		title:    "Открыт info.php (phpinfo) — конфигурация PHP/окружения",
		validate: validatePHPInfo},
	{path: "/swagger.json", sev: store.SevMedium, tags: []string{"api-exposure"},
		title:    "Открыт swagger.json — полная спецификация API",
		validate: validateSwagger},
	{path: "/openapi.json", sev: store.SevMedium, tags: []string{"api-exposure"},
		title:    "Открыт openapi.json — полная спецификация API",
		validate: validateSwagger},
	{path: "/v2/api-docs", sev: store.SevMedium, tags: []string{"api-exposure"},
		title:    "Открыт /v2/api-docs (Swagger) — спецификация API",
		validate: validateSwagger},
	{path: "/swagger-ui/index.html", sev: store.SevLow, tags: []string{"api-exposure"},
		title: "Открыт Swagger UI — интерактивная карта API",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(strings.ToLower(r.body), "swagger-ui"), ""
		}},
	{path: "/graphql", method: "POST", ctype: "application/json",
		reqBody: `{"query":"{__schema{queryType{name}}}"}`,
		sev:     store.SevMedium, tags: []string{"api-exposure", "graphql"},
		title: "GraphQL-интроспекция включена — раскрыта схема API",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "__schema") && strings.Contains(r.body, "queryType"), "отключи introspection в проде"
		}},
	{path: "/.DS_Store", sev: store.SevLow, tags: []string{"info-disclosure"},
		title: "Открыт /.DS_Store — раскрывает имена файлов каталога",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "Bud1"), ""
		}},
	{path: "/crossdomain.xml", sev: store.SevMedium, tags: []string{"misconfig"},
		title: "crossdomain.xml с wildcard — доверие любому домену",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "allow-access-from") && strings.Contains(r.body, `domain="*"`), ""
		}},
	// Бэкапы/дампы: не HTML, статус 200 и либо крупный файл, либо узнаваемый дамп.
	{path: "/backup.sql", sev: store.SevHigh, tags: []string{"backup-leak", "db-dump"},
		title: "Открыт дамп БД /backup.sql", validate: validateDBDump},
	{path: "/database.sql", sev: store.SevHigh, tags: []string{"backup-leak", "db-dump"},
		title: "Открыт дамп БД /database.sql", validate: validateDBDump},
	{path: "/dump.sql", sev: store.SevHigh, tags: []string{"backup-leak", "db-dump"},
		title: "Открыт дамп БД /dump.sql", validate: validateDBDump},
	{path: "/backup.zip", sev: store.SevHigh, tags: []string{"backup-leak"},
		title: "Открыт архив /backup.zip", validate: validateArchive},
	{path: "/backup.tar.gz", sev: store.SevHigh, tags: []string{"backup-leak"},
		title: "Открыт архив /backup.tar.gz", validate: validateArchive},
	{path: "/www.zip", sev: store.SevHigh, tags: []string{"backup-leak"},
		title: "Открыт архив исходников /www.zip", validate: validateArchive},
	{path: "/.env.bak", sev: store.SevHigh, tags: []string{"config-leak", "secret-leak"},
		title: "Открыт бэкап конфига /.env.bak",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && !strings.Contains(r.ct, "html") && reEnv.MatchString(r.body), ""
		}},
	{path: "/wp-config.php.bak", sev: store.SevHigh, tags: []string{"config-leak", "secret-leak"},
		title: "Открыт бэкап wp-config.php — креды WordPress/БД",
		validate: func(r resp) (bool, string) {
			return r.status == 200 && strings.Contains(r.body, "DB_PASSWORD"), ""
		}},
	// security.txt — наоборот, хорошая практика; фиксируем ОТСУТСТВИЕ как info.
	{path: "/.well-known/security.txt", sev: store.SevInfo, tags: []string{"best-practice"},
		title: "Нет /.well-known/security.txt — некуда сообщать об уязвимостях",
		validate: func(r resp) (bool, string) {
			// Находка = файла НЕТ (это рекомендация, а не дыра).
			if r.status == 200 && strings.Contains(strings.ToLower(r.body), "contact") {
				return false, ""
			}
			return true, "добавь security.txt с контактом для white-hat"
		}},
}

func validatePHPInfo(r resp) (bool, string) {
	return r.status == 200 && (strings.Contains(r.body, "phpinfo()") || strings.Contains(r.body, "PHP Version") && strings.Contains(r.body, "Configuration")), ""
}

func validateSwagger(r resp) (bool, string) {
	if r.status != 200 || !strings.Contains(r.ct, "json") {
		return false, ""
	}
	return strings.Contains(r.body, `"swagger"`) || strings.Contains(r.body, `"openapi"`), ""
}

func validateDBDump(r resp) (bool, string) {
	if r.status != 200 || strings.Contains(r.ct, "html") {
		return false, ""
	}
	low := strings.ToLower(r.body)
	if strings.Contains(low, "insert into") || strings.Contains(low, "create table") || strings.Contains(low, "mysql dump") {
		return true, "скачай и проверь — внутри реальные данные клиентов"
	}
	return false, ""
}

func validateArchive(r resp) (bool, string) {
	if r.status != 200 || strings.Contains(r.ct, "html") || strings.Contains(r.ct, "text") {
		return false, ""
	}
	// ZIP начинается с PK\x03\x04; gzip — с 0x1f 0x8b. Либо просто крупный бинарь.
	if strings.HasPrefix(r.body, "PK\x03\x04") || strings.HasPrefix(r.body, "\x1f\x8b") || r.length > 10_000 {
		return true, "архив скачивается анонимно — убрать из веб-корня"
	}
	return false, ""
}

// Run гоняет пробники по живым HTTP(S) URL. В пассивном режиме ничего не шлёт.
func Run(ctx context.Context, rn *runner.Runner, st *store.Store, ev event.Sink, baseURLs []string) {
	if rn.Passive {
		ev.Logln("  пассивный режим: exposure-пробы пропущены (активные запросы)")
		return
	}
	bases := uniqueBases(baseURLs)
	if len(bases) == 0 {
		ev.Logln("  нет живых URL для проверки exposure")
		return
	}
	if len(bases) > maxHosts {
		bases = bases[:maxHosts]
	}
	ev.Logf("  exposure: проверяю %d хостов × %d проб (с валидацией тела)...\n", len(bases), len(checks))

	client := exposureClient
	if rn.SOCKS != "" {
		client = netx.HTTPClient(rn.SOCKS, reqTO, true)
	}

	sem := make(chan struct{}, fetchPool)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var n int

	for _, base := range bases {
		for _, c := range checks {
			wg.Add(1)
			sem <- struct{}{}
			go func(base string, c check) {
				defer wg.Done()
				defer func() { <-sem }()
				u := strings.TrimRight(base, "/") + c.path
				r, ok := probe(ctx, client, rn.Stealthy(), u, c)
				if !ok {
					return
				}
				confirmed, detail := c.validate(r)
				if !confirmed {
					return
				}
				ev2 := "HTTP " + strconv.Itoa(r.status)
				if r.ct != "" {
					ev2 += " · " + r.ct
				}
				if detail != "" {
					detail = strings.ReplaceAll(detail, "<host>", strings.TrimRight(base, "/"))
				}
				tags := append([]string{"exposure"}, c.tags...)
				if st.Add(store.Finding{
					Target: u, Type: store.TypeExposure, Severity: c.sev,
					Title: c.title, Detail: detail, Evidence: ev2,
					Tool: "exposure", Tags: tags,
				}) {
					mu.Lock()
					n++
					mu.Unlock()
					ev.Logf("  exposure [%s]: %s\n", strings.ToUpper(string(c.sev)), u)
				}
			}(base, c)
		}
	}
	wg.Wait()
	ev.Logf("  exposure: подтверждённых находок %d\n", n)
}

// probe выполняет один запрос и читает префикс тела.
func probe(ctx context.Context, client *http.Client, stealthy bool, u string, c check) (resp, bool) {
	cctx, cancel := context.WithTimeout(ctx, reqTO)
	defer cancel()
	method := c.method
	if method == "" {
		method = http.MethodGet
	}
	var bodyRd io.Reader
	if c.reqBody != "" {
		bodyRd = strings.NewReader(c.reqBody)
	}
	req, err := http.NewRequestWithContext(cctx, method, u, bodyRd)
	if err != nil {
		return resp{}, false
	}
	ua := "Mozilla/5.0 (compatible; pentkit/authorized-scan)"
	if stealthy {
		ua = netx.RandomUA()
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if c.ctype != "" {
		req.Header.Set("Content-Type", c.ctype)
	}
	rsp, err := client.Do(req)
	if err != nil {
		return resp{}, false
	}
	defer rsp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(rsp.Body, maxRead))
	return resp{
		status: rsp.StatusCode,
		ct:     strings.ToLower(rsp.Header.Get("Content-Type")),
		length: rsp.ContentLength,
		body:   string(b),
	}, true
}

// uniqueBases берёт только scheme://host[:port] из переданных URL (без путей),
// чтобы не долбить один хост десятками проб из-за разных URL.
func uniqueBases(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		i := strings.Index(u, "://")
		if i < 0 {
			continue
		}
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[:j]
		}
		base := u[:i+3] + rest
		if !seen[base] {
			seen[base] = true
			out = append(out, base)
		}
	}
	// чуть перемешаем, чтобы при обрезке до maxHosts выборка была не только первой пачкой
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

var exposureClient = &http.Client{
	Timeout: reqTO,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	// Не ходим по редиректам: 301 на главную — это не «файл найден».
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

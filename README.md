# pentkit

Один бинарник со **встроенным веб-интерфейсом** для **авторизованного** пентеста.
Собирает в единый пайплайн проверенные опенсорс-тулы Kali, нормализует находки и
генерирует отчёт. Запустил `pentkit serve`, открыл браузер — всё внутри.

```
recon ─▶ fingerprint ─▶ osint ─▶ cloudflare ─▶ crawl ─▶ vuln ─▶ nmap ─▶ exploit ─▶ msf check ─▶ web ─▶ extra ─▶ report
subfinder  whatweb       theHar-  origin за CF   katana  nuclei  -sV   searchsploit  check     ffuf   testssl  MD+HTML
dnsx       wafw00f       vester   (подтвержд.    gau     +FP     NSE   msf .rc       (неинтру-  arjun  nikto
naabu      amass                  подменой Host,         отсев   vuln  (без авто-    зивно)     dalfox wpscan
httpx      assetfinder            Shodan/ST)             +CVE          запуска)                 sqlmap gowitness
```

**Burp-функции — и автоматизированы, и ручной перехват:**
- автоматом: краулинг (katana) + скрытые параметры (arjun) + фаззинг директорий
  (ffuf) + инъекции (dalfox/sqlmap/nuclei `-dast`) + пассивный аудит заголовков;
- вручную: встроенный **перехватывающий прокси (MITM)** с HTTP-историей,
  **Intercept** (hold/forward/drop) и **Repeater** — `pentkit serve` → ссылка
  «🔀 Прокси» (или сразу `/proxy`). Это закрывает Proxy/Intercept/Repeater Burp.

> ⚠️ Запускать только против систем, на тест которых у тебя есть **письменное
> разрешение**. В интерфейсе/конфиге поля scope и «Авторизация» обязательны;
> каждая цель перед сканированием проверяется по scope (страховка от выхода за рамки).

## Сборка

Go, один бинарник, рантайм не нужен. UI вшит в бинарник (Go embed).

```bash
go mod tidy
go build -o pentkit .
```

Кросс-компиляция под Kali:

```bash
GOOS=linux GOARCH=amd64 go build -o pentkit .
```

## Запуск — веб-интерфейс (рекомендуется)

```bash
./pentkit serve
```

В консоли появится ссылка вида `http://127.0.0.1:8777/?t=<токен>`. Открой её в
браузере. Дальше в UI: заполняешь работу/scope/авторизацию, отмечаешь модули
галочками (недоступные тулы подсвечиваются), жмёшь «Запустить» — внизу живой лог,
счётчики находок по важности и таблица находок, кнопка «Отчёт».

- Сервер слушает только `127.0.0.1`, API защищён разовым токеном из ссылки.
- Открыть наружу (осторожно): `./pentkit serve -addr 0.0.0.0:8777`.

## Запуск — CLI (для автоматизации/cron)

```bash
cp config.example.yaml config.yaml   # заполни scope, авторизацию, ключи
./pentkit run    -c config.yaml -v    # полный пайплайн
./pentkit recon  -c config.yaml       # разведка + origin за CF
./pentkit scan   -c config.yaml       # nuclei + takeover + TLS + nikto + nmap + exploit + msf check
./pentkit web    -c config.yaml       # краулинг + веб-тесты + аудит заголовков
./pentkit web    -c config.yaml --sqli # + активные SQL-инъекции (по согласованию)
./pentkit report -c config.yaml       # пересобрать отчёт
```

Результаты: `engagements/<name>/findings.jsonl`, `report.md`, `report.html`,
`screenshots/`.

## Установка тулов на Kali

Любой тул необязателен: если его нет в PATH, шаг пропускается с предупреждением.

```bash
sudo apt update
sudo apt install -y golang-go seclists ffuf nikto nuclei nmap exploitdb metasploit-framework \
  amass assetfinder whatweb wafw00f wpscan sqlmap theharvester sslscan
# ProjectDiscovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
# сбор URL / веб-тесты / скриншоты
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/sensepost/gowitness@latest
pipx install arjun          # или: go install github.com/s0md3v/arjun (через pipx надёжнее)
# testssl
sudo apt install -y testssl.sh   # либо git clone https://github.com/drwetter/testssl.sh
# --- расширенный white-hat набор (v0.5.0) ---
go install -v github.com/tomnomnom/waybackurls@latest        # архивные URL (доп. к gau)
go install -v github.com/tomnomnom/gf@latest                 # сортировка URL по типам инъекций
go install -v github.com/tomnomnom/qsreplace@latest          # (используется паттернами gf)
git clone https://github.com/tomnomnom/gf ~/gf-src && mkdir -p ~/.gf && cp -r ~/gf-src/examples/* ~/.gf/
git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns && cp ~/Gf-Patterns/*.json ~/.gf/
go install -v github.com/LukaSikic/subzy@latest              # subdomain takeover (спец-тул)
cargo install feroxbuster                                    # рекурсивный дирбаст (или apt install feroxbuster)
sudo apt install -y findomain                                # быстрые пассивные поддомены
# SecretFinder (опционально; встроенный regex-скан секретов работает и без него)
pipx install SecretFinder || pip install requests jsbeautifier
# Скрытность: Tor + proxychains
sudo apt install -y tor proxychains4
export PATH="$PATH:$HOME/go/bin"
nuclei -update-templates
```

naabu требует `libpcap-dev`. seclists нужен для словарей ffuf/arjun.

## Модули сканирования

| Модуль | Тулы | Что делает |
|---|---|---|
| recon | subfinder, amass, assetfinder, findomain, dnsx, naabu, httpx | поддомены (4 источника, параллельно) → резолв → порты → HTTP/технологии |
| fingerprint | whatweb, wafw00f | отпечаток технологий/CMS и определение WAF |
| osint | theHarvester | почты и хосты из открытых источников |
| cloudflare | crt.sh, Shodan, SecurityTrails, DNS | детект CF, поиск **и подтверждение** origin в обход WAF |
| crawl | katana, gau, waybackurls, gf | краулинг + архивы + сортировка URL по типам инъекций (xss/sqli/ssrf/lfi/redirect) |
| secrets | встроенный regex, SecretFinder | утечки ключей/токенов (AWS/Google/Slack/GitHub/Stripe/JWT/private key) в JS |
| exposure | встроенный | открытые `.git`/`.svn`/`.env`/бэкапы, Spring `/actuator`(+`/env`,`/heapdump`), Swagger/OpenAPI, GraphQL-интроспекция, phpinfo, `/server-status`, `.htpasswd` — **с валидацией тела** |
| jwt | встроенный, jwt_tool | JWT: `alg:none`, подбор слабого HMAC-секрета (подделываемые токены), подсказка RS256→HS256, токен без `exp` |
| apidisco | kiterunner (kr) | брутфорс скрытых API-эндпоинтов по словарям Assetnote |
| bypass | встроенный | обход `401`/`403` (broken access control): `X-Forwarded-For`/`X-Original-URL`/трюки с путём, **с проверкой результата** |
| authtest (⚠) | встроенный | активная проверка отсутствия rate-limit на `/login`,`/reset` (серия ложных логинов, по согласованию) |
| vuln | nuclei | уязвимости по шаблонам + отсев ложных + перепроверка (в stealth добавляет `X-Forwarded-For: 127.0.0.1` для обхода WAF) |
| web | feroxbuster/ffuf, arjun, dalfox, встроенный клиент | рекурсивный дирбаст, параметры, XSS (+dalfox pipe по gf), CORS-мисконфиг, security-заголовки |
| sqli (⚠) | sqlmap, nuclei -dast | активные SQL-инъекции и DAST-фаззинг по gf-кандидатам (по согласованию) |
| wordpress | wpscan | аудит WordPress-сайтов |
| TLS | testssl | слабые шифры/протоколы, TLS-уязвимости |
| nikto | nikto | базовые проблемы веб-сервера |
| takeover | nuclei, subzy | subdomain takeover (два движка fingerprint'ов) |
| screenshots | gowitness | скриншоты живых сервисов для отчёта |
| nmap | nmap | версии сервисов + NSE-скрипты уязвимостей (CVE) |
| exploit | searchsploit, metasploit | публичные эксплойты Exploit-DB + готовый msf `.rc` |
| msf check | metasploit | неинтрузивное подтверждение уязвимости (`check`, без `exploit`) |

## Cloudflare

Если корневой домен за CF, обычный скан бьёт по WAF. Модуль `cloudflare`:

1. детектит CF по диапазонам IP;
2. собирает кандидатов origin из CT-логов (crt.sh), резолва известных хостов,
   а при наличии ключей — из **Shodan** (поиск по hostname) и **SecurityTrails**
   (история A-записей до перехода на CF);
3. **активно подтверждает** каждый кандидат: шлёт запрос напрямую на IP с подменой
   заголовка `Host` и сравнивает ответ (title/размер тела) с сайтом за WAF. Если
   совпало — origin подтверждён (находка `origin-confirmed`, severity high), и его
   можно сканировать напрямую в обход Cloudflare.

Ключи в `config.yaml` → `keys:` (`shodan`, `securitytrails`) заметно усиливают
поиск origin. Ручная проверка кандидата:

```bash
curl -H "Host: acme.com" --resolve acme.com:443:<origin-ip> https://acme.com/ -k
```

## Отсев ложных срабатываний

- дедуп находок по детерминированному ID (повторный запуск не плодит дубли);
- nuclei: дедуп по (шаблон+хост), шумные теги → info;
- `verify` (по умолчанию вкл.): каждое срабатывание перепроверяется точечным
  повторным прогоном → тег `verified` / `requires-review`.

## Эксплуатация (nmap / searchsploit / Metasploit)

Модуль `exploit` **подтверждает и готовит** эксплуатацию, но **не стреляет сам**:

1. `nmap -sV --script vuln` — версии сервисов и NSE-проверки уязвимостей с CVE;
2. `searchsploit` — публичные эксплойты Exploit-DB по продуктам/версиям/CVE;
3. Metasploit — генерируется `engagements/<name>/metasploit.rc` с импортом
   результатов nmap в БД msf и подобранными `search cve:` по найденным CVE.

Фактическая эксплуатация — ручной шаг под твоим контролем:

```bash
msfconsole -q -r engagements/<name>/metasploit.rc
# в msf: use <module>; set RHOSTS <ip>; check   # неинтрузивная проверка
#        run    # только по согласованным целям
```

Автозапуск эксплойтов по всему скоупу намеренно не делается — он может положить
боевые системы клиента. Модуль **`msf check`** автоматизирует именно безопасную
часть: по найденным CVE подбирает модули Metasploit и вызывает у каждого только
`check` (никогда `run`/`exploit`) против целей, фиксируя вердикт «уязвимо». Это
даёт подтверждение эксплуатируемости без атаки; фактический «выстрел» остаётся
ручным.

**Burp Suite** не нужен как отдельный GUI — автоматизируемые функции закрыты
пайплайном (Spider → katana, Intruder → ffuf/arjun/dalfox/sqlmap, Passive Scanner
→ аудит заголовков, Active Scan → nuclei `-dast`), а ручной перехват и повтор —
встроенным прокси (см. ниже).

## Прокси (Burp-режим): перехват, Intercept, Repeater

`pentkit serve` → в интерфейсе ссылка **«🔀 Прокси»** (или открой `/proxy?t=<токен>`).
Встроенный перехватывающий прокси на чистом Go, без внешних зависимостей:

- **MITM HTTP/HTTPS** — свой корневой CA генерируется при старте, листовые
  сертификаты выпускаются на лету под каждый хост;
- **История** — все запросы/ответы (метод, код, хост, путь, размер), пассивные
  заметки (нет HSTS/CSP, Server, cookie без HttpOnly), фильтр по scope;
- **Intercept** — удержание запроса (hold) с правкой сырого запроса и
  Forward / Drop;
- **Repeater** — повтор произвольного сырого запроса и просмотр ответа.

Настройка браузера: укажи HTTP/HTTPS-прокси `127.0.0.1:8780`, затем импортируй
`pentkit CA` (кнопка «⬇ Скачать CA») как доверенный корневой сертификат (надёжнее
всего — в Firefox, у него своё хранилище). Без импорта CA браузер будет ругаться
на HTTPS. CA и приватный ключ лежат в `pentkit-ca/` (в `.gitignore`).

> ⚠️ Прокси расшифровывает твой HTTPS-трафик. Только своя машина, только
> авторизованный тест. После работы сними прокси и удали CA из браузера.

## Скрытность: Tor и уклонение от WAF/Firewall

У большинства целей стоят WAF/Firewall, которые банят по шумным паттернам и
заносят IP в блок-лист. Три независимых рычага (сочетаются как угодно):

**Tor / свой SOCKS5** — прячет твой реальный IP (не путать с шифрованием: до
выхода из сети Tor трафик зашифрован, дальше до цели шифрует уже HTTPS).
В `config.yaml`:

```yaml
tor: true                      # весь трафик через локальный Tor (127.0.0.1:9050)
# proxy: socks5://127.0.0.1:9050  # или свой SOCKS5 вместо Tor
```

- Внешние тулы заворачиваются в `proxychains4`, Go-клиенты (origin за CF, аудит
  заголовков, апстрим MITM-прокси) ходят через встроенный SOCKS5-клиент;
- DNS резолвится на стороне Tor (`proxy_dns`) — без утечки резолва;
- **raw-скан автоматически переводится в connect-режим** (`naabu -s c`,
  `nmap -sT -Pn`), иначе SYN/UDP-пакеты ушли бы мимо proxychains и
  деанонимизировали. Фрагментация/decoy при Tor недоступны (несовместимы с
  connect через прокси);
- перед стартом pentkit **проверяет, что Tor реально отвечает**, и падает с
  понятной ошибкой, если сервиса нет (не начинает скан «в открытую»).
  Нужны запущенный сервис `tor` (не Tor Browser!) и `proxychains4`
  (`apt install tor proxychains4`).

**Stealth** (`stealth: true` / галочка в UI) — тихий режим против срабатывания
WAF/IPS: низкий rate (по умолчанию 10/с) и concurrency (≤3), джиттер между
запросами, ротация реалистичного User-Agent. Применяется к nmap (`-T2`,
фрагментация вне Tor), ffuf (мало потоков, `-p` джиттер — дирбаст главный триггер
бана), nuclei, sqlmap/dalfox/arjun (задержки), httpx (`-random-agent`).

**Passive** (`--passive` / галочка) — максимально тихо, только разведка без
активного воздействия на цель: поддомены и OSINT из открытых источников,
резолв, лёгкий HTTP-пробинг, отпечаток whatweb. **Отключены** портскан (naabu),
nikto, wafw00f (активные пробы), все инъекции, а подтверждение origin за CF идёт
без прямых запросов (только фиксирует кандидатов).

> ⚠️ Tor может нарушить rules of engagement: клиент часто ждёт трафик с
> известного IP (allowlist/атрибуция). Сверься с договором.

## Безопасность данных

SQL-инъекции (sqlmap) и DAST-фаззинг (nuclei `-dast`) **выключены по умолчанию** —
агрессивный режим может повредить данные клиента. Включаются осознанно: флаг
`--sqli` в CLI или галочка «Активные SQL-инъекции» в UI; даже тогда sqlmap идёт в
щадящем режиме (`--level 1 --risk 1`, без `--dump`/`--os-shell`). `config.yaml`,
`engagements/` и скриншоты исключены из git (`.gitignore`), т.к. содержат данные
клиентов.

## Структура

```
main.go                 CLI (serve/run/recon/scan/web/report)
internal/engine         оркестратор пайплайна (Options)
internal/ui             встроенный веб-интерфейс (index.html + proxy.html)
internal/proxy          перехватывающий прокси (MITM/история/Intercept/Repeater)
internal/event          поток прогресса (консоль / буфер для UI)
internal/config         конфиг (scope, ключи, лимиты)
internal/scope          проверка границ теста
internal/runner         запуск внешних тулов (+ обёртка proxychains, stealth/passive-контекст)
internal/netx           SOCKS5-клиент (Tor), конфиг proxychains, ротация User-Agent
internal/store          единое хранилище находок (JSONL + дедуп)
internal/recon          поддомены → резолв → порты → HTTP
internal/analyze        whatweb/wafw00f/wpscan/theHarvester/amass/assetfinder/findomain
internal/cloudflare     детект CF + поиск и подтверждение origin
internal/crawl          katana + gau + waybackurls + gf-сортировка по типам инъекций
internal/secrets        поиск утечек ключей/токенов в JS (regex + SecretFinder)
internal/exposure       открытые .git/.env/actuator/swagger/бэкапы (с валидацией тела)
internal/apisec         JWT (alg:none/слабый секрет/RS256→HS256) / обход 401-403 / kiterunner / rate-limit входа
internal/vuln           nuclei + отсев FP
internal/web            feroxbuster/ffuf / arjun / dalfox (+pipe) / CORS-аудит
internal/extra          testssl / nikto / takeover (nuclei+subzy) / gowitness
internal/exploit        nmap NSE / searchsploit / Metasploit .rc
internal/report         Markdown + HTML отчёт
```

# pentkit

Оркестратор **авторизованного** пентеста на Go: один бинарник со встроенным веб-UI
(Go embed). Собирает опенсорс-тулы Kali в единый пайплайн, нормализует находки,
генерит отчёт. `pentkit serve` → браузер.

> Только против систем с письменным разрешением. Scope и авторизация обязательны;
> все цели фильтруются по scope — эту страховку не ослаблять.

## Команды

```bash
go build -o pentkit .      # сборка
go test ./...              # тесты
go vet ./...               # статика
GOOS=linux GOARCH=amd64 go build -o pentkit .   # кросс под Kali
```

Модуль: `pentkit` (go 1.22, единственная внешняя зависимость — yaml.v3).

## Структура

- `main.go` — CLI, флаги, запуск пайплайна и `serve`.
- `internal/engine` — оркестрация пайплайна (recon→cloudflare→crawl→vuln→web→extra→report).
- `internal/runner` — запуск внешних тулов.
- `internal/scope` — фильтрация целей по scope (страховка от выхода за рамки).
- `internal/config` — парсинг `config.yaml` (пример: `config.example.yaml`).
- `internal/recon`, `cloudflare`, `crawl`, `vuln`, `web`, `extra`, `exploit`,
  `analyze`, `secrets`, `netx` — стадии/утилиты пайплайна.
- `internal/proxy` — MITM-прокси (Intercept/Repeater, свой CA в `ca.go`).
- `internal/ui` — встроенный веб-интерфейс (`index.html`, `proxy.html`, embed).
- `internal/report` — отчёт MD+HTML. `internal/store` — хранилище прогонов.

## Пайплайн

recon (subfinder/dnsx/naabu/httpx) → fingerprint (whatweb/wafw00f) → osint
→ cloudflare (origin за CF) → crawl (katana/gau) → vuln (nuclei) → nmap → exploit
(searchsploit, msf **без** автозапуска) → web (ffuf/arjun/dalfox/sqlmap) → extra
(testssl/nikto/wpscan) → report.

## Договорённости

- Эксплойт-модули и msf — только ручное подтверждение, без авто-запуска.
- Пиши по-русски (как в README и комментариях).

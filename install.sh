#!/usr/bin/env bash
# install.sh — установка pentkit и всех его тулов одной командой.
#
#   bash install.sh
#
# Делает: ставит Go и git (если нет) → собирает бинарь pentkit →
# доустанавливает пентест-тулы (nuclei, httpx, subfinder, ffuf, nmap,
# sqlmap, metasploit, kr, jwt_tool, …) через встроенную команду `pentkit setup`.
#
# Запускай ОТ ОБЫЧНОГО пользователя (не из-под root): go-тулы встанут в твой
# ~/go/bin, а для apt-пакетов скрипт сам попросит sudo.
set -euo pipefail

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

# --- sudo для системных пакетов ---
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
  warn "Запущено от root — go-тулы встанут в /root/go/bin."
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
  warn "Нет sudo — apt-пакеты поставить не выйдет, встанут только go/pipx-тулы."
fi

# --- 1. Go и git ---
# apt можно использовать, только если он есть И мы root или есть sudo.
can_apt=0
if command -v apt-get >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; }; then
  can_apt=1
fi

if ! command -v go >/dev/null 2>&1; then
  if [ "$can_apt" -eq 1 ]; then
    say "Ставлю Go и git (apt)…"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y golang-go git
  else
    die "Go не найден и apt недоступен. Поставь Go вручную: https://go.dev/dl/"
  fi
fi
if ! command -v git >/dev/null 2>&1 && [ "$can_apt" -eq 1 ]; then
  $SUDO apt-get install -y git
fi

say "Go: $(go version 2>/dev/null || echo '??')"

# --- 2. Сборка pentkit ---
# Скрипт лежит в корне репозитория — работаем из его каталога.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f go.mod ] || die "go.mod не найден — запусти скрипт из каталога репозитория pentkit."
say "Собираю pentkit…"
go build -o pentkit .
say "Готово: $(pwd)/pentkit"

# --- 3. Прогреваем sudo, чтобы setup ставил apt-тулы без запинки ---
# `pentkit setup` вызывает apt через `sudo -n` (без запроса пароля); закэшируем
# креды заранее, чтобы это сработало.
if [ -n "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
  say "Нужен sudo для apt-тулов — введи пароль (один раз):"
  $SUDO -v || warn "sudo не подтверждён — apt-тулы могут пропуститься, go-тулы встанут всё равно."
fi

# --- 4. Установка тулов ---
say "Доустанавливаю пентест-тулы (это займёт время)…"
./pentkit setup || warn "Часть тулов не поставилась — смотри список выше, их можно доставить вручную (README)."

# --- 5. PATH и финал ---
GOBIN="$(go env GOPATH 2>/dev/null)/bin"
case ":$PATH:" in
  *":$GOBIN:"*) ;;
  *) warn "Добавь go-bin в PATH, иначе часть тулов не найдётся:"
     echo "      echo 'export PATH=\"\$PATH:$GOBIN:\$HOME/.local/bin\"' >> ~/.bashrc && source ~/.bashrc" ;;
esac

cat <<'DONE'

==> Установка завершена.

Запуск веб-интерфейса:
    ./pentkit serve
  затем открой показанную ссылку (токен уже в ней).

CLI (полный пайплайн, сам доустанавливает недостающее):
    ./pentkit run -c config.yaml

Проверь готовность тулов в любой момент:
    ./pentkit setup
DONE

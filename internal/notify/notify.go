// Package notify шлёт краткую сводку значимых находок (critical/high) во
// внешние каналы: Telegram, Slack, Discord. Все каналы опциональны — настроен
// тот, для которого задан токен/вебхук. Встроенный HTTP, внешних тулов не надо.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pentkit/internal/config"
	"pentkit/internal/event"
	"pentkit/internal/store"
)

var client = &http.Client{Timeout: 15 * time.Second}

// Run формирует сводку по crit/high находкам и рассылает по настроенным каналам.
func Run(ctx context.Context, cfg *config.Config, st *store.Store, ev event.Sink) {
	n := cfg.Notify
	if n.TelegramToken == "" && n.SlackWebhook == "" && n.DiscordWebhook == "" {
		ev.Logln("  уведомления не настроены (config.notify) — пропускаю")
		return
	}
	msg := buildMessage(cfg.Engagement.Name, st.All(), st.Counts())

	if n.TelegramToken != "" && n.TelegramChat != "" {
		if err := sendTelegram(ctx, n.TelegramToken, n.TelegramChat, msg); err != nil {
			ev.Logf("  ! telegram: %v\n", err)
		} else {
			ev.Logln("  уведомление отправлено в Telegram ✓")
		}
	}
	if n.SlackWebhook != "" {
		if err := sendJSON(ctx, n.SlackWebhook, map[string]string{"text": msg}); err != nil {
			ev.Logf("  ! slack: %v\n", err)
		} else {
			ev.Logln("  уведомление отправлено в Slack ✓")
		}
	}
	if n.DiscordWebhook != "" {
		if err := sendJSON(ctx, n.DiscordWebhook, map[string]string{"content": truncate(msg, 1900)}); err != nil {
			ev.Logf("  ! discord: %v\n", err)
		} else {
			ev.Logln("  уведомление отправлено в Discord ✓")
		}
	}
}

// buildMessage собирает краткую сводку: счётчики + список crit/high (до 15).
func buildMessage(engagement string, findings []store.Finding, counts map[store.Severity]int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🛰️ pentkit — работа «%s»\n", engagement)
	fmt.Fprintf(&b, "Крит: %d · Высок: %d · Средн: %d · Низк: %d\n",
		counts[store.SevCritical], counts[store.SevHigh], counts[store.SevMedium], counts[store.SevLow])

	var top []store.Finding
	for _, f := range findings {
		if f.Severity == store.SevCritical || f.Severity == store.SevHigh {
			top = append(top, f)
		}
	}
	if len(top) == 0 {
		b.WriteString("\nКрит/high находок нет.")
		return b.String()
	}
	b.WriteString("\nЗначимые находки:\n")
	for i, f := range top {
		if i >= 15 {
			fmt.Fprintf(&b, "…и ещё %d\n", len(top)-15)
			break
		}
		fmt.Fprintf(&b, "• [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.Target)
	}
	return b.String()
}

func sendTelegram(ctx context.Context, token, chat, text string) error {
	api := "https://api.telegram.org/bot" + token + "/sendMessage"
	form := url.Values{}
	form.Set("chat_id", chat)
	form.Set("text", truncate(text, 4000))
	form.Set("disable_web_page_preview", "true")
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendJSON(ctx context.Context, webhook string, payload any) error {
	b, _ := json.Marshal(payload)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, webhook, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

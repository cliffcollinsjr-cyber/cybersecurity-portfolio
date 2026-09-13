package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type Alert struct {
	AlertID  string `json:"alert_id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Hostname string `json:"hostname"`
	User     string `json:"user"`
}

type NotifyPayload struct {
	Channel   string `json:"channel"`
	Text      string `json:"text"`
	AlertID   string `json:"alert_id"`
	Severity  string `json:"severity"`
	Hostname  string `json:"hostname"`
	DryRun    bool   `json:"dry_run"`
	Timestamp string `json:"timestamp"`
	Label     string `json:"label"`
}

func redactWebhook(url string) string {
	if url == "" {
		return "(none)"
	}
	if len(url) < 12 {
		return "***"
	}
	return url[:8] + "…REDACTED…"
}

func main() {
	alertPath := flag.String("alert", "", "Path to alert JSON")
	channel := flag.String("channel", "#soc-demo", "Destination channel (demo)")
	webhook := flag.String("webhook", "", "Webhook URL (never printed in full)")
	post := flag.Bool("post", false, "If set with webhook, would POST (still blocked in demo unless ALLOW_POST=1)")
	ticketSync := flag.Bool("ticket-sync", false, "Emit ticket-sync stub record")
	flag.Parse()

	if *alertPath == "" {
		fmt.Fprintln(os.Stderr, "usage: go-notifier --alert <file.json> [--channel #soc-demo] [--ticket-sync]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	data, err := os.ReadFile(*alertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read alert: %v\n", err)
		os.Exit(1)
	}

	var alert Alert
	if err := json.Unmarshal(data, &alert); err != nil {
		fmt.Fprintf(os.Stderr, "parse alert: %v\n", err)
		os.Exit(1)
	}

	text := fmt.Sprintf("[DEMO] %s | %s | host=%s user=%s",
		strings.ToUpper(alert.Severity), alert.Title, alert.Hostname, alert.User)

	payload := NotifyPayload{
		Channel:   *channel,
		Text:      text,
		AlertID:   alert.AlertID,
		Severity:  alert.Severity,
		Hostname:  alert.Hostname,
		DryRun:    true,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Label:     "[DEMO] dry-run notifier — not a live production send",
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)

	fmt.Fprintf(os.Stderr, "webhook=%s post_requested=%v\n", redactWebhook(*webhook), *post)

	if *post && os.Getenv("ALLOW_POST") != "1" {
		fmt.Fprintln(os.Stderr, "POST suppressed (demo). Set ALLOW_POST=1 only in authorized labs.")
	}

	if *ticketSync {
		ticket := map[string]any{
			"action":   "create_or_update",
			"project":  "SOC-DEMO",
			"summary":  alert.Title,
			"severity": alert.Severity,
			"labels":   []string{"demo", "soc-automation"},
			"dry_run":  true,
		}
		fmt.Fprintln(os.Stdout, "--- ticket-sync stub ---")
		_ = enc.Encode(ticket)
	}
}

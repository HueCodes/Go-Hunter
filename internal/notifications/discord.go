package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type DiscordProvider struct {
	WebhookURL string
	Username   string
}

func NewDiscordProvider(webhookURL string) *DiscordProvider {
	return &DiscordProvider{
		WebhookURL: webhookURL,
		Username:   "Go-Hunter",
	}
}

func (d *DiscordProvider) Name() string { return "discord" }

func (d *DiscordProvider) Validate() error {
	if d.WebhookURL == "" {
		return fmt.Errorf("discord webhook URL is required")
	}
	return nil
}

func (d *DiscordProvider) Send(ctx context.Context, n Notification) error {
	color := severityColorInt(n.Severity)

	fields := make([]discordField, 0, len(n.Fields))
	for k, v := range n.Fields {
		fields = append(fields, discordField{Name: k, Value: v, Inline: true})
	}

	payload := discordPayload{
		Username: d.Username,
		Embeds: []discordEmbed{{
			Title:       n.Title,
			Description: n.Message,
			Color:       color,
			Fields:      fields,
			Timestamp:   time.Now().Format(time.RFC3339),
			Footer:      &discordFooter{Text: "Go-Hunter"},
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling discord payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending discord notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord returned status %d", resp.StatusCode)
	}

	return nil
}

type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
	Footer      *discordFooter `json:"footer,omitempty"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func severityColorInt(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0xFF0000
	case SeverityHigh:
		return 0xFF6600
	case SeverityMedium:
		return 0xFFCC00
	case SeverityLow:
		return 0x36A64F
	default:
		return 0x439FE0
	}
}

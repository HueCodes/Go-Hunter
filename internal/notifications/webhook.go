package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type WebhookProvider struct {
	URL    string
	Secret string
}

func NewWebhookProvider(url, secret string) *WebhookProvider {
	return &WebhookProvider{URL: url, Secret: secret}
}

func (w *WebhookProvider) Name() string { return "webhook" }

func (w *WebhookProvider) Validate() error {
	if w.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}
	return nil
}

func (w *WebhookProvider) Send(ctx context.Context, n Notification) error {
	payload := webhookPayload{
		Event:     string(n.EventType),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data: webhookData{
			Title:    n.Title,
			Message:  n.Message,
			Severity: string(n.Severity),
			Fields:   n.Fields,
			URL:      n.URL,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Go-Hunter-Webhook/1.0")

	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Signature-256", "sha256="+signature)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

type webhookPayload struct {
	Event     string      `json:"event"`
	Timestamp string      `json:"timestamp"`
	Data      webhookData `json:"data"`
}

type webhookData struct {
	Title    string            `json:"title"`
	Message  string            `json:"message"`
	Severity string            `json:"severity,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	URL      string            `json:"url,omitempty"`
}

package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SlackProvider struct {
	WebhookURL string
	Channel    string
	Username   string
}

func NewSlackProvider(webhookURL string) *SlackProvider {
	return &SlackProvider{
		WebhookURL: webhookURL,
		Username:   "Go-Hunter",
	}
}

func (s *SlackProvider) Name() string { return "slack" }

func (s *SlackProvider) Validate() error {
	if s.WebhookURL == "" {
		return fmt.Errorf("slack webhook URL is required")
	}
	return nil
}

func (s *SlackProvider) Send(ctx context.Context, n Notification) error {
	color := severityColor(n.Severity)

	fields := make([]slackField, 0, len(n.Fields))
	for k, v := range n.Fields {
		fields = append(fields, slackField{Title: k, Value: v, Short: true})
	}

	payload := slackPayload{
		Username: s.Username,
		Channel:  s.Channel,
		Attachments: []slackAttachment{{
			Color:   color,
			Title:   n.Title,
			Text:    n.Message,
			Fields:  fields,
			Footer:  "Go-Hunter",
			Ts:      time.Now().Unix(),
		}},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}

type slackPayload struct {
	Username    string            `json:"username,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Title  string       `json:"title"`
	Text   string       `json:"text"`
	Fields []slackField `json:"fields,omitempty"`
	Footer string       `json:"footer,omitempty"`
	Ts     int64        `json:"ts,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "#FF0000"
	case SeverityHigh:
		return "#FF6600"
	case SeverityMedium:
		return "#FFCC00"
	case SeverityLow:
		return "#36A64F"
	default:
		return "#439FE0"
	}
}

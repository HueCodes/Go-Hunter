package notifications

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

type EmailProvider struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

func NewEmailProvider(host string, port int, username, password, from string, to []string) *EmailProvider {
	return &EmailProvider{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		From:     from,
		To:       to,
	}
}

func (e *EmailProvider) Name() string { return "email" }

func (e *EmailProvider) Validate() error {
	if e.Host == "" {
		return fmt.Errorf("SMTP host is required")
	}
	if e.From == "" {
		return fmt.Errorf("from address is required")
	}
	if len(e.To) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}
	return nil
}

func (e *EmailProvider) Send(_ context.Context, n Notification) error {
	subject := fmt.Sprintf("[Go-Hunter] %s", n.Title)

	var body strings.Builder
	body.WriteString(n.Message)
	body.WriteString("\n\n")

	if n.Severity != "" {
		body.WriteString(fmt.Sprintf("Severity: %s\n", n.Severity))
	}

	for k, v := range n.Fields {
		body.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}

	if n.URL != "" {
		body.WriteString(fmt.Sprintf("\nView details: %s\n", n.URL))
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		e.From,
		strings.Join(e.To, ", "),
		subject,
		body.String(),
	)

	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)

	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, e.Password, e.Host)
	}

	if err := smtp.SendMail(addr, auth, e.From, e.To, []byte(msg)); err != nil {
		return fmt.Errorf("sending email: %w", err)
	}

	return nil
}

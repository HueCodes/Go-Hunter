package notifications

import (
	"context"
	"log/slog"
	"sync"
)

type Engine struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

func NewEngine() *Engine {
	return &Engine{
		providers: make(map[string]Provider),
	}
}

func (e *Engine) Register(provider Provider) error {
	if err := provider.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers[provider.Name()] = provider
	return nil
}

func (e *Engine) Unregister(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.providers, name)
}

func (e *Engine) Send(ctx context.Context, notification Notification) {
	e.mu.RLock()
	providers := make([]Provider, 0, len(e.providers))
	for _, p := range e.providers {
		providers = append(providers, p)
	}
	e.mu.RUnlock()

	for _, provider := range providers {
		go func(p Provider) {
			if err := p.Send(ctx, notification); err != nil {
				slog.Error("failed to send notification",
					"provider", p.Name(),
					"event", notification.EventType,
					"error", err,
				)
			}
		}(provider)
	}
}

func (e *Engine) Providers() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.providers))
	for name := range e.providers {
		names = append(names, name)
	}
	return names
}

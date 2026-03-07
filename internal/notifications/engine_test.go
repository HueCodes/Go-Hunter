package notifications

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type mockProvider struct {
	name        string
	validateErr error
	sendErr     error
	mu          sync.Mutex
	sent        []Notification
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Validate() error { return m.validateErr }
func (m *mockProvider) Send(_ context.Context, n Notification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, n)
	return m.sendErr
}
func (m *mockProvider) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func TestEngine_RegisterAndProviders(t *testing.T) {
	e := NewEngine()
	p := &mockProvider{name: "test"}

	if err := e.Register(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	providers := e.Providers()
	if len(providers) != 1 || providers[0] != "test" {
		t.Errorf("Providers() = %v, want [test]", providers)
	}
}

func TestEngine_RegisterValidationError(t *testing.T) {
	e := NewEngine()
	p := &mockProvider{name: "bad", validateErr: errors.New("invalid config")}

	if err := e.Register(p); err == nil {
		t.Fatal("expected validation error")
	}

	if len(e.Providers()) != 0 {
		t.Error("provider should not be registered after validation failure")
	}
}

func TestEngine_Unregister(t *testing.T) {
	e := NewEngine()
	p := &mockProvider{name: "test"}
	e.Register(p)

	e.Unregister("test")
	if len(e.Providers()) != 0 {
		t.Error("provider should be removed after Unregister")
	}
}

func TestEngine_Send(t *testing.T) {
	e := NewEngine()
	p1 := &mockProvider{name: "p1"}
	p2 := &mockProvider{name: "p2"}
	e.Register(p1)
	e.Register(p2)

	n := Notification{
		EventType: EventNewFinding,
		Title:     "Test Finding",
		Message:   "A test finding was created",
		Severity:  SeverityCritical,
	}

	e.Send(context.Background(), n)

	// Wait for goroutines to complete
	time.Sleep(50 * time.Millisecond)

	if p1.sentCount() != 1 {
		t.Errorf("p1 sent = %d, want 1", p1.sentCount())
	}
	if p2.sentCount() != 1 {
		t.Errorf("p2 sent = %d, want 1", p2.sentCount())
	}
}

func TestEngine_SendWithError(t *testing.T) {
	e := NewEngine()
	p := &mockProvider{name: "failing", sendErr: errors.New("network error")}
	e.Register(p)

	// Should not panic even when provider returns error
	e.Send(context.Background(), Notification{
		EventType: EventScanFailed,
		Title:     "Scan Failed",
	})

	time.Sleep(50 * time.Millisecond)
	// Provider was still called
	if p.sentCount() != 1 {
		t.Errorf("sent = %d, want 1", p.sentCount())
	}
}

func TestEngine_SendNoProviders(t *testing.T) {
	e := NewEngine()
	// Should not panic with no providers
	e.Send(context.Background(), Notification{Title: "test"})
}

func TestEngine_RegisterOverwrite(t *testing.T) {
	e := NewEngine()
	p1 := &mockProvider{name: "same"}
	p2 := &mockProvider{name: "same"}
	e.Register(p1)
	e.Register(p2)

	if len(e.Providers()) != 1 {
		t.Error("registering same name should overwrite")
	}
}

package circuitbreaker

import (
	"errors"
	"testing"
	"time"
)

func TestClosedState_AllowsRequests(t *testing.T) {
	cb := New(3, 100*time.Millisecond)
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cb.State() != StateClosed {
		t.Errorf("state = %v, want Closed", cb.State())
	}
}

func TestClosedToOpen_AfterMaxFailures(t *testing.T) {
	cb := New(3, 100*time.Millisecond)
	testErr := errors.New("fail")

	for i := 0; i < 3; i++ {
		cb.Execute(func() error { return testErr })
	}

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want Open", cb.State())
	}

	err := cb.Execute(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestOpenToHalfOpen_AfterTimeout(t *testing.T) {
	cb := New(2, 50*time.Millisecond)
	testErr := errors.New("fail")

	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	if cb.State() != StateOpen {
		t.Fatalf("state = %v, want Open", cb.State())
	}

	time.Sleep(60 * time.Millisecond)

	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("expected success in half-open, got %v", err)
	}

	if cb.State() != StateClosed {
		t.Errorf("state = %v, want Closed after success in half-open", cb.State())
	}
}

func TestHalfOpen_FailureReopens(t *testing.T) {
	cb := New(2, 50*time.Millisecond)
	testErr := errors.New("fail")

	cb.Execute(func() error { return testErr })
	cb.Execute(func() error { return testErr })

	time.Sleep(60 * time.Millisecond)

	cb.Execute(func() error { return testErr })

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want Open after half-open failure", cb.State())
	}
}

func TestReset(t *testing.T) {
	cb := New(1, time.Second)
	cb.Execute(func() error { return errors.New("fail") })

	if cb.State() != StateOpen {
		t.Fatalf("state = %v, want Open", cb.State())
	}

	cb.Reset()
	if cb.State() != StateClosed {
		t.Errorf("state = %v, want Closed after reset", cb.State())
	}
}

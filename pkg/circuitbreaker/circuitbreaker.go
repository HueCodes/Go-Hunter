package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker is open")

type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

type CircuitBreaker struct {
	mu               sync.Mutex
	state            State
	failures         int
	successes        int
	maxFailures      int
	resetTimeout     time.Duration
	halfOpenMaxCalls int
	lastFailure      time.Time
}

func New(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		maxFailures:      maxFailures,
		resetTimeout:     resetTimeout,
		halfOpenMaxCalls: 1,
	}
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.allowRequest(); err != nil {
		return err
	}

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailure = time.Now()
		if cb.state == StateHalfOpen || cb.failures >= cb.maxFailures {
			cb.state = StateOpen
		}
		return err
	}

	cb.successes++
	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.failures = 0
		cb.successes = 0
	}
	return nil
}

func (cb *CircuitBreaker) allowRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return nil
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = StateHalfOpen
			cb.successes = 0
			return nil
		}
		return ErrCircuitOpen
	case StateHalfOpen:
		if cb.successes >= cb.halfOpenMaxCalls {
			return ErrCircuitOpen
		}
		return nil
	}
	return nil
}

func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
}

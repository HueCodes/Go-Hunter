package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestRequestID_GeneratesNewID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Context().Value(RequestIDKey)
		if id == nil {
			t.Fatal("expected request ID in context, got nil")
		}
		idStr, ok := id.(string)
		if !ok {
			t.Fatalf("expected request ID to be string, got %T", id)
		}
		if _, err := uuid.Parse(idStr); err != nil {
			t.Fatalf("expected valid UUID in context, got %q: %v", idStr, err)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get("X-Request-ID")
	if respID == "" {
		t.Fatal("expected X-Request-ID response header to be set")
	}
	if _, err := uuid.Parse(respID); err != nil {
		t.Fatalf("expected valid UUID in response header, got %q: %v", respID, err)
	}
}

func TestRequestID_UsesExistingHeader(t *testing.T) {
	existingID := "my-custom-request-id-12345"

	var contextID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = r.Context().Value(RequestIDKey).(string)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if contextID != existingID {
		t.Fatalf("expected context request ID %q, got %q", existingID, contextID)
	}
	if got := rec.Header().Get("X-Request-ID"); got != existingID {
		t.Fatalf("expected response header X-Request-ID %q, got %q", existingID, got)
	}
}

func TestRequestID_SetsResponseHeader(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get("X-Request-ID")
	if respID == "" {
		t.Fatal("expected X-Request-ID response header to be set")
	}
}

func TestRequestID_ContextAndHeaderMatch(t *testing.T) {
	var contextID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = r.Context().Value(RequestIDKey).(string)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	headerID := rec.Header().Get("X-Request-ID")
	if contextID != headerID {
		t.Fatalf("context ID %q does not match response header ID %q", contextID, headerID)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	var ids []string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids = append(ids, r.Context().Value(RequestIDKey).(string))
	}))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate request ID generated: %s", id)
		}
		seen[id] = true
	}
}

func TestGetRequestID_WithValue(t *testing.T) {
	expectedID := "test-request-id-abc"
	ctx := context.WithValue(context.Background(), RequestIDKey, expectedID)

	got := GetRequestID(ctx)
	if got != expectedID {
		t.Fatalf("GetRequestID() = %q, want %q", got, expectedID)
	}
}

func TestGetRequestID_WithoutValue(t *testing.T) {
	got := GetRequestID(context.Background())
	if got != "" {
		t.Fatalf("GetRequestID() = %q, want empty string", got)
	}
}

func TestGetRequestID_WithWrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), RequestIDKey, 12345)

	got := GetRequestID(ctx)
	if got != "" {
		t.Fatalf("GetRequestID() = %q, want empty string for wrong type", got)
	}
}

func TestRequestID_CallsNextHandler(t *testing.T) {
	called := false
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestRequestID_EmptyHeaderGeneratesUUID(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	respID := rec.Header().Get("X-Request-ID")
	if _, err := uuid.Parse(respID); err != nil {
		t.Fatalf("expected valid UUID for empty header, got %q: %v", respID, err)
	}
}

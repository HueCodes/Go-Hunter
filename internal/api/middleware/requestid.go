package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

const RequestIDKey contextKey = "request_id"
const requestIDHeader = "X-Request-ID"

// RequestID generates or propagates a request ID for tracing.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID returns the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// LoggerContextKey is the context key for the request-scoped logger.
// Exported as a variable so other packages can retrieve it without circular imports.
const LoggerContextKey contextKey = "logger"

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Logging logs each request with structured attributes and injects a
// request-scoped logger into the context so downstream code can use
// LoggerFromContext to get a logger that automatically includes request_id.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Build a request-scoped logger with request_id
			reqLogger := logger
			if reqID := GetRequestID(r.Context()); reqID != "" {
				reqLogger = logger.With("request_id", reqID)
			}

			// Store scoped logger in context
			ctx := context.WithValue(r.Context(), LoggerContextKey, reqLogger)
			r = r.WithContext(ctx)

			wrapped := &responseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			reqLogger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.status,
				"size", wrapped.size,
				"duration_ms", duration.Milliseconds(),
				"ip", r.RemoteAddr,
			)
		})
	}
}

// LoggerFromContext returns the request-scoped logger from the context.
// Falls back to the default slog logger if none is set.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(LoggerContextKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

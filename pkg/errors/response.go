package errors

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorResponse is the JSON structure returned to API clients.
type ErrorResponse struct {
	Code    string            `json:"code"`
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

// WriteHTTP writes the AppError as a JSON HTTP response.
// Internal errors are logged but never exposed to the client.
func WriteHTTP(w http.ResponseWriter, r *http.Request, err *AppError) {
	if err.Internal != nil {
		slog.ErrorContext(r.Context(), "internal error",
			"error", err.Internal,
			"code", err.Code,
			"status", err.Status,
			"path", r.URL.Path,
			"method", r.Method,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Code:    err.Code,
		Error:   err.Message,
		Details: err.Details,
	})
}

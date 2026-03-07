package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// Standard sentinel errors for matching with errors.Is.
var (
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrConflict     = errors.New("conflict")
	ErrValidation   = errors.New("validation error")
	ErrInternal     = errors.New("internal error")
	ErrUnavailable  = errors.New("service unavailable")
)

// AppError is a domain error that carries an HTTP status code, a machine-readable
// code, a user-safe message, and an optional internal error for logging.
type AppError struct {
	// Status is the HTTP status code to return.
	Status int `json:"-"`
	// Code is a machine-readable error code (e.g. "not_found", "validation_error").
	Code string `json:"code"`
	// Message is a user-safe error message.
	Message string `json:"error"`
	// Details contains field-level validation errors.
	Details map[string]string `json:"details,omitempty"`
	// Internal is the underlying error for server-side logging. Never exposed to clients.
	Internal error `json:"-"`
}

func (e *AppError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Internal)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Internal
}

// NotFound creates a 404 error.
func NotFound(resource string) *AppError {
	return &AppError{
		Status:  http.StatusNotFound,
		Code:    "not_found",
		Message: resource + " not found",
	}
}

// Unauthorized creates a 401 error.
func Unauthorized(msg string) *AppError {
	return &AppError{
		Status:  http.StatusUnauthorized,
		Code:    "unauthorized",
		Message: msg,
	}
}

// Forbidden creates a 403 error.
func Forbidden(msg string) *AppError {
	return &AppError{
		Status:  http.StatusForbidden,
		Code:    "forbidden",
		Message: msg,
	}
}

// Conflict creates a 409 error.
func Conflict(msg string) *AppError {
	return &AppError{
		Status:  http.StatusConflict,
		Code:    "conflict",
		Message: msg,
	}
}

// Validation creates a 400 validation error with field-level details.
func Validation(details map[string]string) *AppError {
	return &AppError{
		Status:  http.StatusBadRequest,
		Code:    "validation_error",
		Message: "Validation failed",
		Details: details,
	}
}

// BadRequest creates a 400 error.
func BadRequest(msg string) *AppError {
	return &AppError{
		Status:  http.StatusBadRequest,
		Code:    "bad_request",
		Message: msg,
	}
}

// Internal creates a 500 error. The cause is logged but never exposed.
func Internal(msg string, cause error) *AppError {
	return &AppError{
		Status:   http.StatusInternalServerError,
		Code:     "internal_error",
		Message:  msg,
		Internal: cause,
	}
}

// Unavailable creates a 503 error.
func Unavailable(msg string) *AppError {
	return &AppError{
		Status:  http.StatusServiceUnavailable,
		Code:    "service_unavailable",
		Message: msg,
	}
}

// Wrap wraps an internal error with a user-facing message and status.
func Wrap(status int, msg string, cause error) *AppError {
	code := "internal_error"
	switch {
	case status == http.StatusBadRequest:
		code = "bad_request"
	case status == http.StatusUnauthorized:
		code = "unauthorized"
	case status == http.StatusForbidden:
		code = "forbidden"
	case status == http.StatusNotFound:
		code = "not_found"
	case status == http.StatusConflict:
		code = "conflict"
	case status == http.StatusServiceUnavailable:
		code = "service_unavailable"
	}
	return &AppError{
		Status:   status,
		Code:     code,
		Message:  msg,
		Internal: cause,
	}
}

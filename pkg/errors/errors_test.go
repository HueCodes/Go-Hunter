package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestNotFound(t *testing.T) {
	err := NotFound("Asset")
	if err.Status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", err.Status, http.StatusNotFound)
	}
	if err.Code != "not_found" {
		t.Errorf("code = %s, want not_found", err.Code)
	}
	if err.Message != "Asset not found" {
		t.Errorf("message = %s, want 'Asset not found'", err.Message)
	}
}

func TestUnauthorized(t *testing.T) {
	err := Unauthorized("Invalid token")
	if err.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", err.Status, http.StatusUnauthorized)
	}
	if err.Code != "unauthorized" {
		t.Errorf("code = %s, want unauthorized", err.Code)
	}
}

func TestValidation(t *testing.T) {
	details := map[string]string{"email": "required"}
	err := Validation(details)
	if err.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", err.Status, http.StatusBadRequest)
	}
	if err.Details["email"] != "required" {
		t.Errorf("missing detail for email")
	}
}

func TestInternal(t *testing.T) {
	cause := errors.New("db connection failed")
	err := Internal("Something went wrong", cause)
	if err.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", err.Status, http.StatusInternalServerError)
	}
	if err.Internal != cause {
		t.Error("internal error not preserved")
	}
	if err.Error() != "Something went wrong: db connection failed" {
		t.Errorf("error string = %q", err.Error())
	}
}

func TestUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := Internal("wrapper", cause)
	if !errors.Is(err, cause) {
		t.Error("Unwrap should expose the internal error")
	}
}

func TestAppError_NilInternal(t *testing.T) {
	err := NotFound("User")
	if err.Error() != "User not found" {
		t.Errorf("error string = %q", err.Error())
	}
}

func TestWrap(t *testing.T) {
	tests := []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, "bad_request"},
		{http.StatusUnauthorized, "unauthorized"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusNotFound, "not_found"},
		{http.StatusConflict, "conflict"},
		{http.StatusServiceUnavailable, "service_unavailable"},
		{http.StatusInternalServerError, "internal_error"},
	}

	for _, tt := range tests {
		err := Wrap(tt.status, "msg", nil)
		if err.Code != tt.code {
			t.Errorf("Wrap(%d) code = %s, want %s", tt.status, err.Code, tt.code)
		}
	}
}

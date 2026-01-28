package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/auth"
)

type AuthHandler struct {
	authService *auth.Service
}

func NewAuthHandler(authService *auth.Service) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	resp, err := h.authService.Register(r.Context(), auth.RegisterInput{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		OrgName:  req.OrgName,
	})

	if err != nil {
		switch err {
		case auth.ErrUserExists:
			writeJSON(w, http.StatusConflict, dto.ErrorResponse{Error: "User already exists"})
		default:
			writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Registration failed"})
		}
		return
	}

	// Set cookie for web dashboard (same as login)
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	writeJSON(w, http.StatusCreated, dto.AuthResponse{
		Token: resp.Token,
		User: dto.UserDTO{
			ID:             resp.User.ID.String(),
			Email:          resp.User.Email,
			Name:           resp.User.Name,
			Role:           resp.User.Role,
			OrganizationID: resp.User.OrganizationID.String(),
			OrgName:        resp.User.Organization.Name,
		},
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		writeJSON(w, http.StatusBadRequest, dto.ErrorResponse{Error: "Validation failed", Details: errors})
		return
	}

	resp, err := h.authService.Login(r.Context(), auth.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			writeJSON(w, http.StatusUnauthorized, dto.ErrorResponse{Error: "Invalid credentials"})
		case auth.ErrInactiveUser:
			writeJSON(w, http.StatusForbidden, dto.ErrorResponse{Error: "Account is inactive"})
		default:
			writeJSON(w, http.StatusInternalServerError, dto.ErrorResponse{Error: "Login failed"})
		}
		return
	}

	// Set cookie for web dashboard
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	writeJSON(w, http.StatusOK, dto.AuthResponse{
		Token: resp.Token,
		User: dto.UserDTO{
			ID:             resp.User.ID.String(),
			Email:          resp.User.Email,
			Name:           resp.User.Name,
			Role:           resp.User.Role,
			OrganizationID: resp.User.OrganizationID.String(),
			OrgName:        resp.User.Organization.Name,
		},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, dto.SuccessResponse{Message: "Logged out"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

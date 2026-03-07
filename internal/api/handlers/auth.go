package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/hugh/go-hunter/internal/api/dto"
	"github.com/hugh/go-hunter/internal/auth"
	apperrors "github.com/hugh/go-hunter/pkg/errors"
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
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
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
			apperrors.WriteHTTP(w, r, apperrors.Conflict("User already exists"))
		default:
			apperrors.WriteHTTP(w, r, apperrors.Internal("Registration failed", err))
		}
		return
	}

	setAuthCookie(w, resp.Token)

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
		apperrors.WriteHTTP(w, r, apperrors.BadRequest("Invalid request body"))
		return
	}

	if errs := req.Validate(); len(errs) > 0 {
		apperrors.WriteHTTP(w, r, apperrors.Validation(errs))
		return
	}

	resp, err := h.authService.Login(r.Context(), auth.LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			apperrors.WriteHTTP(w, r, apperrors.Unauthorized("Invalid credentials"))
		case auth.ErrInactiveUser:
			apperrors.WriteHTTP(w, r, apperrors.Forbidden("Account is inactive"))
		default:
			apperrors.WriteHTTP(w, r, apperrors.Internal("Login failed", err))
		}
		return
	}

	setAuthCookie(w, resp.Token)

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

func setAuthCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

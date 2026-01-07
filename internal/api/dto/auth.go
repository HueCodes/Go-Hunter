package dto

import (
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	OrgName  string `json:"org_name,omitempty"`
}

func (r RegisterRequest) Validate() map[string]string {
	errors := make(map[string]string)

	// Email validation
	r.Email = strings.TrimSpace(r.Email)
	if r.Email == "" {
		errors["email"] = "Email is required"
	} else if len(r.Email) > 254 {
		errors["email"] = "Email is too long"
	} else if !emailRegex.MatchString(r.Email) {
		errors["email"] = "Invalid email format"
	}

	// Password validation
	if r.Password == "" {
		errors["password"] = "Password is required"
	} else if len(r.Password) < 8 {
		errors["password"] = "Password must be at least 8 characters"
	} else if len(r.Password) > 128 {
		errors["password"] = "Password is too long"
	}

	// Name validation
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		errors["name"] = "Name is required"
	} else if len(r.Name) > 100 {
		errors["name"] = "Name is too long"
	}

	// Org name validation (optional)
	if r.OrgName != "" && len(r.OrgName) > 100 {
		errors["org_name"] = "Organization name is too long"
	}

	return errors
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r LoginRequest) Validate() map[string]string {
	errors := make(map[string]string)

	if r.Email == "" {
		errors["email"] = "Email is required"
	}
	if r.Password == "" {
		errors["password"] = "Password is required"
	}

	return errors
}

type AuthResponse struct {
	Token string  `json:"token"`
	User  UserDTO `json:"user"`
}

type UserDTO struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	OrganizationID string `json:"organization_id"`
	OrgName        string `json:"org_name,omitempty"`
}

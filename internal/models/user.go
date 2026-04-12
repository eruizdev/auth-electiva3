package models

// User representa un usuario en la base de datos
type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"` // nunca se devuelve en JSON
	Role     string `json:"role"`
}

// RegisterRequest es lo que llega al registrar un usuario
type RegisterRequest struct {
	Name     string `json:"name"     binding:"required"`
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role"` // opcional, default CLIENT
}

// LoginRequest es lo que llega al hacer login
type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// TokenResponse es lo que se devuelve al cliente
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

// RefreshRequest es lo que llega al renovar token
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

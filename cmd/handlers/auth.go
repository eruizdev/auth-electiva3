package handlers

import (
	"auth-service/internal/db"
	"auth-service/internal/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Register crea un nuevo usuario
func Register(c *gin.Context) {
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role == "" {
		req.Role = "CLIENT"
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error encriptando contraseña"})
		return
	}

	var userID int
	err = db.DB.QueryRow(
		`INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id`,
		req.Name, req.Email, string(hashedPassword), req.Role,
	).Scan(&userID)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "El email ya está registrado"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Usuario registrado", "user_id": userID})
}

// Login valida credenciales y devuelve tokens
func Login(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := db.DB.QueryRow(
		`SELECT id, name, email, password, role FROM users WHERE email = $1`,
		req.Email,
	).Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Role)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales inválidas"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales inválidas"})
		return
	}

	accessToken, refreshToken, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generando tokens"})
		return
	}

	saveRefreshToken(user.ID, refreshToken)
	c.SetCookie("access_token", accessToken, 3600, "/", "", false, true)

	c.JSON(http.StatusOK, models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	})
}

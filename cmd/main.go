package main

import (
	"auth-service/internal/db"
	"auth-service/internal/handlers"
	"auth-service/internal/middleware"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	// Conectar a la base de datos
	db.Connect()

	// Crear router de Gin
	router := gin.Default()

	// ── Rutas públicas (sin token) ──
	public := router.Group("/auth")
	{
		public.POST("/register", handlers.Register)
		public.POST("/login", handlers.Login)
		public.POST("/refresh", handlers.Refresh)
		public.POST("/logout", handlers.Logout)
	}

	// ── Rutas protegidas (requieren token) ──
	protected := router.Group("/auth")
	protected.Use(middleware.AuthRequired())
	{
		protected.GET("/me", handlers.Me)
	}

	log.Println("Auth Service corriendo en puerto 8081")
	router.Run(":8081")
}

package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func Connect() {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)

	var err error
	DB, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Error abriendo DB: ", err)
	}

	// Reintentar conexion hasta 15 veces (espera a que Postgres este listo)
	for i := 0; i < 15; i++ {
		if err = DB.Ping(); err == nil {
			break
		}
		log.Printf("DB no lista, reintento %d/15...", i+1)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatal("No se pudo conectar a DB: ", err)
	}

	createTables()
	log.Println("Auth DB conectada")
}

func createTables() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id         SERIAL PRIMARY KEY,
		name       VARCHAR(100) NOT NULL,
		email      VARCHAR(100) UNIQUE NOT NULL,
		password   VARCHAR(255) NOT NULL,
		role       VARCHAR(20)  NOT NULL DEFAULT 'CLIENT',
		created_at TIMESTAMP    DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id         SERIAL PRIMARY KEY,
		user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token      TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT NOW()
	);`

	_, err := DB.Exec(query)
	if err != nil {
		log.Fatal("Error creando tablas: ", err)
	}

	crearAdminPorDefecto()
}

// crearAdminPorDefecto inserta un usuario admin si no existe
func crearAdminPorDefecto() {
	// Hash bcrypt de la contraseña "admin123"
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error generando hash admin:", err)
		return
	}

	// INSERT solo si no existe ese email (ON CONFLICT no hace nada)
	_, err = DB.Exec(
		`INSERT INTO users (name, email, password, role)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (email) DO NOTHING`,
		"Administrador", "admin@velkyvet.com", string(hash), "ADMIN",
	)
	if err != nil {
		log.Println("Error creando admin:", err)
		return
	}
	log.Println("Admin por defecto listo: admin@velkyvet.com / admin123")
}
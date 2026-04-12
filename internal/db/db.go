package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/lib/pq"
)

// DB es la conexión global a la base de datos
var DB *sql.DB

// Connect abre la conexión y crea las tablas si no existen
func Connect() {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
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

	if err = DB.Ping(); err != nil {
		log.Fatal("Error conectando a DB: ", err)
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
}

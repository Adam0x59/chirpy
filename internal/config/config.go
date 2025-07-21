package config

import (
	"database/sql"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/adam0x59/chirpy/internal/database"
)

type Config struct {
	DB             *sql.DB
	FileserverHits atomic.Int32
	Queries        *database.Queries
	JWTSecret      string
}

func New() (*Config, error) {
	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWTSECRET")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}

	queries := database.New(db)
	return &Config{DB: db, Queries: queries, JWTSecret: jwtSecret}, nil
}

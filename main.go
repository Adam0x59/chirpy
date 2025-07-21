package main

import (
	"log"
	"net/http"

	"github.com/adam0x59/chirpy/internal/config"
	"github.com/adam0x59/chirpy/internal/handlers"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}
	mux := handlers.NewRouter(cfg)
	server := &http.Server{Addr: ":8080", Handler: mux}
	log.Printf("Serving on port: %q\n", server.Addr)
	log.Fatal(server.ListenAndServe())
}

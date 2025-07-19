package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/adam0x59/chirpy/internal/database"
	"github.com/joho/godotenv"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening connection to database: %s", err)
	}
	dbQueries := database.New(db)
	const filepathRoot = "."
	const port = "8080"
	apiCfg := apiConfig{dbQueries: dbQueries}
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(filepathRoot)))))
	mux.HandleFunc("GET /api/healthz", healthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetMetrics)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	server := &http.Server{Addr: ":" + port, Handler: mux}
	log.Printf("Serving on port: %q\n", port)
	log.Fatal(server.ListenAndServe())
}

func healthz(resp http.ResponseWriter, req *http.Request) {
	respHeader := resp.Header()
	respHeader["Content-Type"] = []string{"text/plain; charset=utf-8"}
	resp.WriteHeader(200)
	resp.Write([]byte("OK\n"))
}

func (cfg *apiConfig) metrics(resp http.ResponseWriter, req *http.Request) {
	respHeader := resp.Header()
	respHeader["Content-Type"] = []string{"text/html; charset=utf-8"}
	resp.WriteHeader(http.StatusOK)
	str := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits.Load())
	resp.Write([]byte(str))
}

func (cfg *apiConfig) resetMetrics(resp http.ResponseWriter, req *http.Request) {
	respHeader := resp.Header()
	respHeader["Content-Type"] = []string{"text/plain; charset=utf-8"}
	resp.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
	resp.Write([]byte("Metrics successfully reset!\n"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type Chirp struct {
	Body string `json:"body"`
}

func validateChirp(resp http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	chirpBody := Chirp{}
	err := decoder.Decode(&chirpBody)
	if err != nil {
		msg := "Something went wrong"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	} else {
		if len(chirpBody.Body) <= 140 {
			respondJSON(resp, http.StatusOK, languagePolice(chirpBody))
			return
		} else {
			msg := "Chirp is too long"
			respondWithError(resp, http.StatusBadRequest, msg, err)
			return
		}
	}
}

func respondWithError(resp http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Println(err)
	}
	if code > 499 {
		log.Printf("Responding with 5XX erorr: %s", msg)
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondJSON(resp, code, errorResponse{Error: msg})
}

func respondJSON(resp http.ResponseWriter, code int, response interface{}) {
	resp.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling response: %s", err)
		resp.WriteHeader(500)
		return
	}
	resp.WriteHeader(code)
	resp.Write(dat)
}

type CleanChirp struct {
	Body string `json:"cleaned_body"`
}

func languagePolice(chirpBody Chirp) CleanChirp {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	split := strings.Split(chirpBody.Body, " ")
	for i, word := range split {
		lword := strings.ToLower(word)
		for _, badWord := range badWords {
			if lword == badWord {
				split[i] = "****"
				break
			}
		}
	}
	return CleanChirp{Body: strings.Join(split, " ")}
}

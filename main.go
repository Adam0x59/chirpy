package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/adam0x59/chirpy/internal/auth"
	"github.com/adam0x59/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	jwtSecret      string
}

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWTSECRET")
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Error opening connection to database: %s", err)
	}
	dbQueries := database.New(db)
	const filepathRoot = "."
	const port = "8080"
	apiCfg := apiConfig{dbQueries: dbQueries, jwtSecret: jwtSecret}
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(filepathRoot)))))
	mux.HandleFunc("GET /api/healthz", healthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirp)
	mux.HandleFunc("POST /api/users", apiCfg.createUser)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirp)
	mux.HandleFunc("POST /api/login", apiCfg.login)
	mux.HandleFunc("POST /api/refresh", apiCfg.refresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.revoke)
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

func (cfg *apiConfig) reset(resp http.ResponseWriter, req *http.Request) {
	respHeader := resp.Header()
	respHeader["Content-Type"] = []string{"text/plain; charset=utf-8"}
	resp.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
	resp.Write([]byte("Metrics successfully reset!\n"))
	cfg.dbQueries.DeleteUsers(req.Context())
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type returnedUser struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	AccessToken  string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

func (cfg *apiConfig) createUser(resp http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	userBody := userRequest{}
	err := decoder.Decode(&userBody)
	if err != nil {
		msg := "Something went wrong"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	hashedPass, err := auth.HashPassword(userBody.Password)
	if err != nil {
		msg := "Error hasing password"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
	}
	args := database.CreateUserParams{
		Email:          userBody.Email,
		HashedPassword: hashedPass,
	}
	usr, err := cfg.dbQueries.CreateUser(req.Context(), args)
	if err != nil {
		msg := "Error creating user"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	respStruct := returnedUser{
		ID:        usr.ID,
		CreatedAt: usr.CreatedAt,
		UpdatedAt: usr.UpdatedAt,
		Email:     usr.Email,
	}
	respondJSON(resp, http.StatusCreated, respStruct)
}

type UserGetReturn struct {
	ID             uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Email          string
	HashedPassword string
}

func (cfg *apiConfig) login(resp http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	userBody := userRequest{}
	err := decoder.Decode(&userBody)
	if err != nil {
		msg := "Error decoding login info"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	userGet, err := cfg.dbQueries.GetUserInfo(req.Context(), userBody.Email)
	if err != nil {
		msg := "Incorrect email or password"
		respondWithError(resp, http.StatusUnauthorized, msg, err)
		return
	}
	err = auth.CheckPasswordHash(userBody.Password, userGet.HashedPassword)
	if err != nil {
		msg := "Incorrect email or password"
		respondWithError(resp, http.StatusUnauthorized, msg, err)
		return
	}
	AccessToken, err := auth.MakeJWT(userGet.ID, cfg.jwtSecret, 0)
	if err != nil {
		msg := "Error creating JWT"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	RefreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		msg := "Error getting refresh token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
	}

	RefreshTokenExpiry := time.Now().Add(time.Hour * 60 * 24)
	args := database.CreateRefreshTokenParams{
		Token:     RefreshToken,
		UserID:    userGet.ID,
		ExpiresAt: RefreshTokenExpiry,
	}
	_, err = cfg.dbQueries.CreateRefreshToken(req.Context(), args)
	if err != nil {
		msg := "Error creating refresh token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	//fmt.Println(refreshToken)
	response := returnedUser{
		ID:           userGet.ID,
		CreatedAt:    userGet.CreatedAt,
		UpdatedAt:    userGet.UpdatedAt,
		Email:        userGet.Email,
		AccessToken:  AccessToken,
		RefreshToken: RefreshToken,
	}
	respondJSON(resp, http.StatusOK, response)
}

type TokenRefreshAccess struct {
	Token string `json:"token"`
}

func (cfg *apiConfig) refresh(resp http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		msg := "Error retrieving refresh token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	tokenData, err := cfg.dbQueries.GetRefreshToken(req.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			msg := "Unauthorized"
			respondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		msg := "Error retrieving token details"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	if tokenData.ExpiresAt.Before(time.Now()) {
		msg := "Unauthorized"
		respondWithError(resp, http.StatusUnauthorized, msg, err)
		return
	}
	if tokenData.RevokedAt.Valid {
		msg := "Unauthorized"
		respondWithError(resp, http.StatusUnauthorized, msg, nil)
		return
	}
	newAuth, err := auth.MakeJWT(tokenData.UserID, cfg.jwtSecret, 0)
	if err != nil {
		msg := "Error creating new access token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}

	respondJSON(resp, http.StatusOK, TokenRefreshAccess{Token: newAuth})
}

func (cfg *apiConfig) revoke(resp http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		msg := "Error getting token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	args := database.RevokeRefreshTokenParams{
		Token:     refreshToken,
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		UpdatedAt: time.Now(),
	}
	cfg.dbQueries.RevokeRefreshToken(req.Context(), args)
	resp.WriteHeader(http.StatusNoContent)
}

type Chirp struct {
	Body    string    `json:"body"`
	User_id uuid.UUID `json:"user_id"`
}

type ReturnedChirp struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) chirp(resp http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		msg := "Error getting token"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	user_auth, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		msg := "Unauthorised"
		respondWithError(resp, http.StatusUnauthorized, msg, err)
		return
	}
	decoder := json.NewDecoder(req.Body)
	chirpBody := Chirp{}
	err = decoder.Decode(&chirpBody)
	if err != nil {
		msg := "Something went wrong"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	chirpBody.User_id = user_auth
	if len(chirpBody.Body) <= 140 {
		chirpReq := database.CreateChirpParams{
			Body:   chirpBody.Body,
			UserID: chirpBody.User_id,
		}
		chirpReq.Body = languagePolice(chirpReq.Body)
		chir, err := cfg.dbQueries.CreateChirp(req.Context(), chirpReq)
		if err != nil {
			msg := "Error creating chirp"
			respondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		retChir := ReturnedChirp{
			Id:        chir.ID,
			CreatedAt: chir.CreatedAt,
			UpdatedAt: chir.UpdatedAt,
			Body:      chir.Body,
			UserId:    chir.UserID,
		}
		respondJSON(resp, http.StatusCreated, retChir)
		return
	}
	msg := "Chirp is too long"
	respondWithError(resp, http.StatusBadRequest, msg, errors.New(msg))
}

func (cfg *apiConfig) getChirps(resp http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(req.Context())
	if err != nil {
		msg := "Error fetching chirps"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	retChirps := []ReturnedChirp{}
	for _, chirp := range chirps {
		retChirps = append(retChirps, ReturnedChirp{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
		})
	}
	respondJSON(resp, http.StatusOK, retChirps)
}

func (cfg *apiConfig) getChirp(resp http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		msg := "Error parsing chirp ID"
		respondWithError(resp, http.StatusInternalServerError, msg, err)
		return
	}
	chirp, err := cfg.dbQueries.GetChirp(req.Context(), id)
	if err != nil {
		msg := "Error fetching chirp"
		respondWithError(resp, http.StatusNotFound, msg, err)
		return
	}
	returnedChirp := ReturnedChirp{
		Id:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserId:    chirp.UserID,
	}
	respondJSON(resp, http.StatusOK, returnedChirp)
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
	resp.Write([]byte("\n"))
}

type CleanChirp struct {
	Body string `json:"cleaned_body"`
}

func languagePolice(chirpBody string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	split := strings.Split(chirpBody, " ")
	for i, word := range split {
		lword := strings.ToLower(word)
		for _, badWord := range badWords {
			if lword == badWord {
				split[i] = "****"
				break
			}
		}
	}
	return strings.Join(split, " ")
}

package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/adam0x59/chirpy/internal/auth"
	"github.com/adam0x59/chirpy/internal/config"
	"github.com/adam0x59/chirpy/internal/database"
	"github.com/google/uuid"
)

type ChirpInput struct {
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

type CleanChirp struct {
	Body string `json:"cleaned_body"`
}

func CreateChirp(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			msg := "Error getting token"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		user_auth, err := auth.ValidateJWT(token, cfg.JWTSecret)
		if err != nil {
			msg := "Unauthorised"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		decoder := json.NewDecoder(req.Body)
		chirpBody := ChirpInput{}
		err = decoder.Decode(&chirpBody)
		if err != nil {
			msg := "Something went wrong"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		chirpBody.User_id = user_auth
		if len(chirpBody.Body) <= 140 {
			chirpReq := database.CreateChirpParams{
				Body:   chirpBody.Body,
				UserID: chirpBody.User_id,
			}
			chirpReq.Body = CleanInput(chirpReq.Body)
			chir, err := cfg.Queries.CreateChirp(req.Context(), chirpReq)
			if err != nil {
				msg := "Error creating chirp"
				RespondWithError(resp, http.StatusInternalServerError, msg, err)
				return
			}
			retChir := ReturnedChirp{
				Id:        chir.ID,
				CreatedAt: chir.CreatedAt,
				UpdatedAt: chir.UpdatedAt,
				Body:      chir.Body,
				UserId:    chir.UserID,
			}
			RespondJSON(resp, http.StatusCreated, retChir)
			return
		}
		msg := "chirp is too long"
		RespondWithError(resp, http.StatusBadRequest, msg, errors.New(msg))
	}
}

func GetChirps(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		chirps, err := cfg.Queries.GetChirps(req.Context())
		if err != nil {
			msg := "Error fetching chirps"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
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
		RespondJSON(resp, http.StatusOK, retChirps)
	}
}

func GetChirp(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		id, err := uuid.Parse(req.PathValue("chirpID"))
		if err != nil {
			msg := "Error parsing chirp ID"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		chirp, err := cfg.Queries.GetChirp(req.Context(), id)
		if err != nil {
			msg := "Error fetching chirp"
			RespondWithError(resp, http.StatusNotFound, msg, err)
			return
		}
		returnedChirp := ReturnedChirp{
			Id:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserId:    chirp.UserID,
		}
		RespondJSON(resp, http.StatusOK, returnedChirp)
	}
}

func DeleteChirp(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		id, err := uuid.Parse(req.PathValue("chirpID"))
		if err != nil {
			msg := "Error parsing chirp ID"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			msg := "Error getting token"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		user_auth, err := auth.ValidateJWT(token, cfg.JWTSecret)
		if err != nil {
			msg := "Unauthorised"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		chirp, err := cfg.Queries.GetChirp(req.Context(), id)
		if err != nil {
			msg := "Error fetching chirp"
			RespondWithError(resp, http.StatusNotFound, msg, err)
			return
		}
		if chirp.UserID != user_auth {
			msg := "error, user not authorized"
			RespondWithError(resp, http.StatusForbidden, msg, fmt.Errorf("%s", msg))
			return
		}
		err = cfg.Queries.DeleteChirp(req.Context(), id)
		if err != nil {
			msg := "error deleting chirp"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		resp.WriteHeader(http.StatusNoContent)
	}
}

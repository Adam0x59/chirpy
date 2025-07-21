package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/adam0x59/chirpy/internal/auth"
	"github.com/adam0x59/chirpy/internal/config"
	"github.com/adam0x59/chirpy/internal/database"
	"github.com/google/uuid"
)

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

type UserGetReturn struct {
	ID             uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Email          string
	HashedPassword string
}

type TokenRefreshAccess struct {
	Token string `json:"token"`
}

func CreateUser(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		userBody := userRequest{}
		err := decoder.Decode(&userBody)
		if err != nil {
			msg := "Something went wrong"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		hashedPass, err := auth.HashPassword(userBody.Password)
		if err != nil {
			msg := "Error hasing password"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
		}
		args := database.CreateUserParams{
			Email:          userBody.Email,
			HashedPassword: hashedPass,
		}
		usr, err := cfg.Queries.CreateUser(req.Context(), args)
		if err != nil {
			msg := "Error creating user"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		respStruct := returnedUser{
			ID:        usr.ID,
			CreatedAt: usr.CreatedAt,
			UpdatedAt: usr.UpdatedAt,
			Email:     usr.Email,
		}
		RespondJSON(resp, http.StatusCreated, respStruct)
	}
}

func Login(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		userBody := userRequest{}
		err := decoder.Decode(&userBody)
		if err != nil {
			msg := "Error decoding login info"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		userGet, err := cfg.Queries.GetUserInfo(req.Context(), userBody.Email)
		if err != nil {
			msg := "Incorrect email or password"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		err = auth.CheckPasswordHash(userBody.Password, userGet.HashedPassword)
		if err != nil {
			msg := "Incorrect email or password"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		AccessToken, err := auth.MakeJWT(userGet.ID, cfg.JWTSecret, 0)
		if err != nil {
			msg := "Error creating JWT"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		RefreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			msg := "Error getting refresh token"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
		}

		RefreshTokenExpiry := time.Now().Add(time.Hour * 60 * 24)
		args := database.CreateRefreshTokenParams{
			Token:     RefreshToken,
			UserID:    userGet.ID,
			ExpiresAt: RefreshTokenExpiry,
		}
		_, err = cfg.Queries.CreateRefreshToken(req.Context(), args)
		if err != nil {
			msg := "Error creating refresh token"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		response := returnedUser{
			ID:           userGet.ID,
			CreatedAt:    userGet.CreatedAt,
			UpdatedAt:    userGet.UpdatedAt,
			Email:        userGet.Email,
			AccessToken:  AccessToken,
			RefreshToken: RefreshToken,
		}
		RespondJSON(resp, http.StatusOK, response)
	}
}

func Refresh(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		token, err := auth.GetBearerToken(req.Header)
		if err != nil {
			msg := "Error retrieving refresh token"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		tokenData, err := cfg.Queries.GetRefreshToken(req.Context(), token)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				msg := "Unauthorized"
				RespondWithError(resp, http.StatusUnauthorized, msg, err)
				return
			}
			msg := "Error retrieving token details"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		if tokenData.ExpiresAt.Before(time.Now()) {
			msg := "Unauthorized"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		if tokenData.RevokedAt.Valid {
			msg := "Unauthorized"
			RespondWithError(resp, http.StatusUnauthorized, msg, nil)
			return
		}
		newAuth, err := auth.MakeJWT(tokenData.UserID, cfg.JWTSecret, 0)
		if err != nil {
			msg := "Error creating new access token"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}

		RespondJSON(resp, http.StatusOK, TokenRefreshAccess{Token: newAuth})
	}
}

func Revoke(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		refreshToken, err := auth.GetBearerToken(req.Header)
		if err != nil {
			msg := "Error getting token"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		args := database.RevokeRefreshTokenParams{
			Token:     refreshToken,
			RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
			UpdatedAt: time.Now(),
		}
		cfg.Queries.RevokeRefreshToken(req.Context(), args)
		resp.WriteHeader(http.StatusNoContent)
	}
}

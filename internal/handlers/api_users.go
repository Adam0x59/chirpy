package handlers

import (
	"database/sql"
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

type userRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type returnedUser struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
	AccessToken  string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type returnedUserAbreviated struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
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

type WebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		User_id string `json:"user_id"`
	} `json:"data"`
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
		respStruct := returnedUserAbreviated{
			ID:          usr.ID,
			CreatedAt:   usr.CreatedAt,
			UpdatedAt:   usr.UpdatedAt,
			Email:       usr.Email,
			IsChirpyRed: usr.IsChirpyRed,
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
			IsChirpyRed:  userGet.IsChirpyRed,
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

func UpdateUser(cfg *config.Config) http.HandlerFunc {
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
		userBody := userRequest{}
		err = decoder.Decode(&userBody)
		if err != nil {
			msg := "Something went wrong"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		hashedPass, err := auth.HashPassword(userBody.Password)
		if err != nil {
			msg := "Error hashing password"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
		}
		args := database.UpdateUserParams{
			Email:          userBody.Email,
			HashedPassword: hashedPass,
			ID:             user_auth,
		}
		usr, err := cfg.Queries.UpdateUser(req.Context(), args)
		if err != nil {
			msg := "Error updating user"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		respStruct := returnedUserAbreviated{
			ID:          usr.ID,
			CreatedAt:   usr.CreatedAt,
			UpdatedAt:   usr.UpdatedAt,
			Email:       usr.Email,
			IsChirpyRed: usr.IsChirpyRed,
		}
		RespondJSON(resp, http.StatusOK, respStruct)
	}
}

func UpgradeRed(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		apiKey, err := auth.GetAPIkey(req.Header)
		if err != nil {
			msg := "Unauthorized"
			RespondWithError(resp, http.StatusUnauthorized, msg, err)
			return
		}
		if apiKey != cfg.PolkaApiKey {
			msg := "Unauthorized"
			RespondWithError(resp, http.StatusUnauthorized, msg, fmt.Errorf("%s", msg))
			return
		}
		decoder := json.NewDecoder(req.Body)
		webhook := WebhookRequest{}
		err = decoder.Decode(&webhook)
		if err != nil {
			msg := "Error decoding webhook request"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		if webhook.Event != "user.upgraded" {
			resp.WriteHeader(http.StatusNoContent)
			return
		}
		userID, err := uuid.Parse(webhook.Data.User_id)
		if err != nil {
			msg := "error parsing user_id"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
			return
		}
		args := database.UpdateChirpyRedParams{
			IsChirpyRed: true,
			ID:          userID,
		}
		err = cfg.Queries.UpdateChirpyRed(req.Context(), args)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				msg := "user not found"
				RespondWithError(resp, http.StatusNotFound, msg, err)
				return
			}
			msg := "error updating user to chirpy red"
			RespondWithError(resp, http.StatusInternalServerError, msg, err)
		}
		resp.WriteHeader(http.StatusNoContent)
	}
}

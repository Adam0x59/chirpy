package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(hashedPass), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	baseTimeUnit := time.Second
	jwtExpiry := baseTimeUnit * 3600
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtExpiry)),
		Subject:   userID.String(),
	})
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, errors.New("invalid user ID in token")
	}
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authStr := headers.Get("Authorization")
	if authStr == "" {
		return "", errors.New("no auth header")
	}
	authSplit := strings.Split(authStr, " ")
	if len(authSplit) != 2 || strings.ToLower(authSplit[0]) != "bearer" {
		return "", errors.New("invalid header auth format")
	}
	//fmt.Println(authSplit[1])
	return authSplit[1], nil
}

func MakeRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("error getting random number as: %w", err)
	}
	return hex.EncodeToString(token), nil
}

func GetAPIkey(headers http.Header) (string, error) {
	apiStr := headers.Get("Authorization")
	if apiStr == "" {
		return "", errors.New("no auth header")
	}
	apiSplit := strings.Split(apiStr, " ")
	if len(apiSplit) != 2 || strings.ToLower(apiSplit[0]) != "apikey" {
		return "", errors.New("invalid header api format")
	}
	return apiSplit[1], nil
}

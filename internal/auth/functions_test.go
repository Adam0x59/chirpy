package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashAndCheckPassword_Success(t *testing.T) {
	password := "mysecurepassword"

	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	err = CheckPasswordHash(password, hashed)
	if err != nil {
		t.Errorf("expected password to match hash, got error: %v", err)
	}
}

func TestCheckPasswordHash_Fail(t *testing.T) {
	password := "correct-password"
	wrongPassword := "wrong-password"

	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	err = CheckPasswordHash(wrongPassword, hashed)
	if err == nil {
		t.Error("expected password check to fail, but it succeeded")
	}
}

func TestHashPassword_NonDeterministic(t *testing.T) {
	password := "repeatable-password"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("error hashing password the first time: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("error hashing password the second time: %v", err)
	}

	if hash1 == hash2 {
		t.Error("expected different hashes for same password due to salting, but got identical hashes")
	}
}

func TestMakeAndValidateJWT(t *testing.T) {
	secret := "test-secret"
	userID := uuid.New()
	expiresIn := time.Minute * 15

	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("unexpected error creating JWT: %v", err)
	}

	parsedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("unexpected error validating JWT: %v", err)
	}
	if parsedID != userID {
		t.Errorf("expected userID %v, got %v", userID, parsedID)
	}
}

func TestValidateJWT_InvalidSignature(t *testing.T) {
	secret := "correct-secret"
	userID := uuid.New()
	token, err := MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("unexpected error creating JWT: %v", err)
	}

	// Validate using the wrong secret
	_, err = ValidateJWT(token, "wrong-secret")
	if err == nil {
		t.Error("expected validation to fail with wrong secret, but it succeeded")
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	userID := uuid.New()

	// Create a token that already expired
	token, err := MakeJWT(userID, secret, -time.Minute)
	if err != nil {
		t.Fatalf("unexpected error creating JWT: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Error("expected validation to fail for expired token, but it succeeded")
	}
}

func TestGetBearerToken_ValidateTokenParse(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer test-token-123")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token != "test-token-123" {
		t.Errorf("expected token 'test-token-123', got '%s'", token)
	}
}

func TestGetBearerToken_ValidateFormatFail(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "test-token-123")

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("Error should not be nil, expecting: invalid header auth format")
	}
	if err != nil {
		t.Logf("correct error returned as: %s", err)
	}
	if token != "" {
		t.Errorf("token returned as %s, should be empty", token)
	}
}

func TestGetBearerToken_MissingHeader(t *testing.T) {
	headers := http.Header{}
	// No Authorization set

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("expected error for missing Authorization header, got nil")
	} else {
		t.Logf("correct error returned: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, got: %s", token)
	}
}

func TestGetBearerToken_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Basic some-token")

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("expected error for non-bearer scheme, got nil")
	} else {
		t.Logf("correct error returned: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, got: %s", token)
	}
}

func TestGetBearerToken_TooManyParts(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer token extra-part")

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("expected error for malformed header with too many parts, got nil")
	} else {
		t.Logf("correct error returned: %s", err)
	}

	if token != "" {
		t.Errorf("expected empty token, got: %s", token)
	}
}

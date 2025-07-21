package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adam0x59/chirpy/internal/config"
	"github.com/adam0x59/chirpy/internal/handlers"
)

func TestAdminMetrics(t *testing.T) {
	// Arrange
	cfg := &config.Config{}
	cfg.FileserverHits.Store(42) // simulate some visits

	req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
	w := httptest.NewRecorder()

	handler := handlers.AdminMetrics(cfg)

	// Act
	handler(w, req)

	// Assert
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 OK, got %d", resp.StatusCode)
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("unexpected Content-Type: %s", contentType)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Chirpy has been visited 42 times") {
		t.Errorf("expected visit count in response body, got: %q", body)
	}
}

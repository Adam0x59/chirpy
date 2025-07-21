package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adam0x59/chirpy/internal/config"
)

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	Healthz(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain; charset=utf-8" {
		t.Errorf("unexpected Content-Type: %s", contentType)
	}

	body := w.Body.String()
	if strings.TrimSpace(body) != "OK" {
		t.Errorf("expected body to be 'OK', got: %q", body)
	}
}

func TestMiddlewareMetricsCountFileServerRequests(t *testing.T) {
	cfg := &config.Config{}
	cfg.FileserverHits.Store(0)

	// A dummy handler to wrap
	finalHandlerCalled := false
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the dummy handler with the middleware
	middleware := MiddlewareMetricsCountFileServerRequests(cfg)
	handler := middleware(finalHandler)

	// Send a request through it
	req := httptest.NewRequest(http.MethodGet, "/app/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Assertions
	if !finalHandlerCalled {
		t.Error("final handler was not called")
	}

	if cfg.FileserverHits.Load() != 1 {
		t.Errorf("expected FileserverHits to be 1, got %d", cfg.FileserverHits.Load())
	}

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("expected status OK from final handler, got %d", w.Result().StatusCode)
	}
}

package handlers

import (
	"fmt"
	"net/http"

	"github.com/adam0x59/chirpy/internal/config"
)

func AdminMetrics(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		respHeader := resp.Header()
		respHeader["Content-Type"] = []string{"text/html; charset=utf-8"}
		resp.WriteHeader(http.StatusOK)
		str := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.FileserverHits.Load())
		resp.Write([]byte(str))
	}
}

func AdminReset(cfg *config.Config) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		respHeader := resp.Header()
		respHeader["Content-Type"] = []string{"text/plain; charset=utf-8"}
		resp.WriteHeader(http.StatusOK)
		cfg.FileserverHits.Store(0)
		resp.Write([]byte("Metrics successfully reset!\n"))
		cfg.Queries.DeleteUsers(req.Context())
	}
}

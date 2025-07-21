package handlers

import (
	"net/http"

	"github.com/adam0x59/chirpy/internal/config"
)

func NewRouter(cfg *config.Config) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("/app/", http.StripPrefix("/app", MiddlewareMetricsCountFileServerRequests(cfg)(http.FileServer(http.Dir(".")))))

	mux.HandleFunc("GET /admin/metrics", AdminMetrics(cfg))
	mux.HandleFunc("POST /admin/reset", AdminReset(cfg))
	mux.HandleFunc("GET /api/healthz", Healthz)
	mux.HandleFunc("POST /api/chirps", CreateChirp(cfg))
	mux.HandleFunc("GET /api/chirps", GetChirps(cfg))
	mux.HandleFunc("GET /api/chirps/{chirpID}", GetChirp(cfg))
	mux.HandleFunc("POST /api/users", CreateUser(cfg))
	mux.HandleFunc("POST /api/login", Login(cfg))
	mux.HandleFunc("POST /api/refresh", Refresh(cfg))
	mux.HandleFunc("POST /api/revoke", Revoke(cfg))

	return mux
}

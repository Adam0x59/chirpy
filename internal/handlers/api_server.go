package handlers

import (
	"net/http"

	"github.com/adam0x59/chirpy/internal/config"
)

func Healthz(resp http.ResponseWriter, req *http.Request) {
	respHeader := resp.Header()
	respHeader["Content-Type"] = []string{"text/plain; charset=utf-8"}
	resp.WriteHeader(200)
	resp.Write([]byte("OK\n"))
}

func MiddlewareMetricsCountFileServerRequests(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg.FileserverHits.Add(1)
			next.ServeHTTP(w, r)
		})
	}
}

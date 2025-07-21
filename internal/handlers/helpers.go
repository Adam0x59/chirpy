package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func RespondWithError(resp http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Println(err)
	}
	if code > 499 {
		log.Printf("Responding with 5XX erorr: %s", msg)
	}
	type errorResponse struct {
		Error string `json:"error"`
	}
	RespondJSON(resp, code, errorResponse{Error: msg})
}

func RespondJSON(resp http.ResponseWriter, code int, response interface{}) {
	resp.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling response: %s", err)
		resp.WriteHeader(500)
		return
	}
	resp.WriteHeader(code)
	resp.Write(dat)
	resp.Write([]byte("\n"))
}

func CleanInput(chirpBody string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	split := strings.Split(chirpBody, " ")
	for i, word := range split {
		lword := strings.ToLower(word)
		for _, badWord := range badWords {
			if lword == badWord {
				split[i] = "****"
				break
			}
		}
	}
	return strings.Join(split, " ")
}

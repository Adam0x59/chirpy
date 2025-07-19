package main

import (
	"log"
	"net/http"
)

type ServeMux struct {
}

func main() {
	const port = "8080"
	mux := http.NewServeMux()
	server := &http.Server{Addr: ":" + port, Handler: mux}
	log.Printf("Serving on port: %q\n", port)
	log.Fatal(server.ListenAndServe())
}

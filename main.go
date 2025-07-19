package main

import (
	"log"
	"net/http"
)

func main() {
	//Config
	const port = "8080"
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(".")))

	//Server
	server := &http.Server{Addr: ":" + port, Handler: mux}
	log.Printf("Serving on port: %q\n", port)
	log.Fatal(server.ListenAndServe())
}

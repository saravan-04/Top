package main

import (
	"log"
	"net/http"
	"os"

	"top/handlers"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8085"
	}

	http.HandleFunc("/workload", handlers.HandleWorkload)   // new: ConMan-merged endpoint
	http.HandleFunc("/contract", handlers.HandleContract)   // legacy: accepts pre-built contract
	http.HandleFunc("/contracts/", handlers.HandleGetContract)

	log.Println("TOP running on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

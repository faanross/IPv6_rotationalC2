package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"io"
	"log"
	"net/http"
	"time"
)

const addr string = "[::]"
const port int = 8080

func main() {
	router := chi.NewRouter()

	SetupRoutes(router)

	log.Printf("Server starting on %s:%d...\n", addr, port)

	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", addr, port), router); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

func SetupRoutes(router *chi.Mux) {
	// Register handler for both the root path and /ep
	router.Post("/", RootHandler)
}

func RootHandler(w http.ResponseWriter, r *http.Request) {
	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	fmt.Printf("[%s] Received connection from %s, data size: %d bytes\n",
		time.Now().Format("15:04:05"),
		r.RemoteAddr,
		len(body))

	w.Write([]byte("Request received"))
}

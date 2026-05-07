package main

import (
	"fmt"
	"log"
	"net/http"

	"magazine.ia/modules/auth" // Adjust module path if different
)

const jwtSecret = "supersecretjwtkey" // IMPORTANT: In a real app, use an environment variable for this secret

func main() {
	// Initialize Auth Service
	authService := auth.NewAuthService(jwtSecret)

	// Serve static files from the public directory
	http.Handle("/", http.FileServer(http.Dir("./public")))

	// API Health Check
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"status\":\"online\",\"engine\":\"IAPP Forge GO\"}")
	})

	// Authentication Endpoints
	http.HandleFunc("/api/register", authService.Register)
	http.HandleFunc("/api/login", authService.Login)

	// Protected Endpoint Example
	http.HandleFunc("/api/profile", authService.AuthMiddleware(authService.Profile))

	fmt.Println("🚀 magazine ia running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

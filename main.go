package main

import (
	"fmt"
	"net/http"
)

func main() {

	http.Handle("/", http.FileServer(http.Dir("./public")))

	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"status\":\"online\",\"engine\":\"IAPP Forge GO\"}")
	})

	fmt.Println("🚀 magazine ia running on http://localhost:8080")

	http.ListenAndServe(":8080", nil)
}

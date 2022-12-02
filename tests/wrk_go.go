package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	responseBody := "abcdefghijklmnopqrstuvwxyz"

	http.HandleFunc("/", func (w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		fmt.Fprintf(w, responseBody)
	})

	http.ListenAndServe(":8080", nil)
}

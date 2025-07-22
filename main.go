package main

import (
	"fmt"
	"net/http"
	"time"
)

type Login struct {
	HashedPassword string
	SessionToken	string
	CSRFToken		string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	if len(username) < 8 {
        http.Error(w, "Username must be at least 8 characters", http.StatusBadRequest)
        return
    }

	if !isValidPassword(password) {
        http.Error(w, "Password must be at least 8 characters, contain upper and lower case letters, a number, and a symbol", http.StatusBadRequest)
        return
    }

	if _, exists := users[username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword := hashPassword(password)
	users[username] = Login{HashedPassword: hashedPassword}
	fmt.Fprintf(w, "User %s registered successfully", username)
}
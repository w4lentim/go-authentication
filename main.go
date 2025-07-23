package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/w4lentim/go-authentication/utils"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var users = map[string]Login{}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	//http.HandleFunc("/logout", logout)
	//http.HandleFunc("/protected", protected)
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

	if !utils.IsValidPassword(password) {
		http.Error(w, "Password must be at least 8 characters, contain upper and lower case letters, a number, and a symbol", http.StatusBadRequest)
		return
	}

	if _, exists := users[username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, _ := utils.HashPassword(password)
	users[username] = Login{HashedPassword: hashedPassword}
	fmt.Fprintf(w, "User %s registered successfully", username)
}

func login(w http.ResponseWriter, r *http.Request) {
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

	user, exists := users[username]
	if !exists || !utils.CheckPasswordHash(password, user.HashedPassword) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate session and CSRF tokens
	sessionToken := utils.GenerateToken()
	csrfToken := utils.GenerateToken()

	// Update user session token and store token in the database
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	// Set session token cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	// Set CSRF token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    user.CSRFToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, // CSRF token should be accessible via JavaScript
	})

	fmt.Fprintf(w, "Login successful.")
}

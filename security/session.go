package security

import (
	"errors"
	"net/http"
)

var AuthenticationError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, exists := users[username]
	// Check if the user exists
	if !exists {
		return AuthenticationError
	}
	// Check if the session token is present in the request
	sessionToken, err := r.Cookie("session_token")
	if err != nil {
		return AuthenticationError
	}
	// Check if the session token matches the user's session token
	if sessionToken == nil || sessionToken.Value == "" {
		return AuthenticationError
	}
	if user.SessionToken == "" {
		return AuthenticationError
	}
	// Compare the session token from the request with the user's session token
	if sessionToken.Value != user.SessionToken {
		return AuthenticationError
	}

	// Here you would typically check the session token against a database or cache
	// For simplicity, we assume a valid session token is "valid_session_token"
	if sessionToken.Value != "valid_session_token" {
		return AuthenticationError
	}

	return nil
}

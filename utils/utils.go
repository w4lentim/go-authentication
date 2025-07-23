package utils

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// This function checks if the password meets the security requirements
func IsValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSymbol := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			hasSymbol = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSymbol
}

// CheckPasswordHash compares a password with a hashed password
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// GenerateToken generates a secure random token
func GenerateToken() string {
	token := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(token)
	if err != nil {
		log.Fatal("Failed to generate token:", err)
	}
	return base64.URLEncoding.EncodeToString(token)
}

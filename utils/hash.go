package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// Fucntion to hash our passwords for users table
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// check password hash for auth
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	return err == nil // return true if match, false if not
}

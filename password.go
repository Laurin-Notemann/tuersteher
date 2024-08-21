package tuersteher

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Takes password and password to confirm in, in case the users don't need to 
// confirm their password on register pass the password in for both values
// 
// ValidatePassword checks if the password match and if it is between 8 and 127
// characters
func ValidatePassword(password , confirmPassword string) error {
	if password != confirmPassword {
		return errors.New("Password and confirmed password don't match.")
	}

	if (len(password) <= 7){
    return errors.New("Password is too small, Minium of 8 is needed.") 
  }

  if (len(password) > 128) {
    return errors.New("Password is too big, Maximum of 127 is allowed.")
	}

	return nil
}

func HashPassword(password, salt string) string {
	return string(argon2.IDKey([]byte(password), []byte(salt), 2, 32*1024, 4, 32))
}

// Password refers to the user entered password (e.g. on signIn)
// storedSalt refers to the salt that is stored alongside the user and hashed password
// storedHashedPw refers to the password that is stored belonging to the user
func ComparePassword(password, storedSalt, storedHashedPw string) error {
	hashedPassword := HashPassword(password, storedSalt)
	// 0 means not the same
	if subtle.ConstantTimeCompare([]byte(hashedPassword), []byte(storedHashedPw)) == 0 {
		return errors.New("Failed to compare passwords.")
	}
	return nil
}

// Size is the amount of byte 32 = 256 bits
func GenerateRandomString(size int) (string, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

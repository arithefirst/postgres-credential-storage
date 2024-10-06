package postgres_credential_storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/lib/pq"
	"math/rand"
)

// PostgresConnection Connection Details for postgres server
type PostgresConnection struct {
	Host string
	Port int
	User string
	Pass string
	Db   string
	SSL  bool
}

// Generates a 32 long random character string
func generateSalt() string {
	charSet := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&()*+,-./:;<=>?@[\\]^_{|}~"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet)-1)]
	}
	return string(b)
}

// SetPassword Set password in the database
func SetPassword(username string, password string, connectionStr PostgresConnection) error {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.SSL {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.Host, connectionStr.Port, connectionStr.User, connectionStr.Pass,
		connectionStr.Db, ssl)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return err
	}

	// Defer the disconnect
	defer func() {
		err := db.Close()
		if err != nil {
			panic(err)
		}
	}()

	// Generate Salt
	salt := generateSalt()

	// Salt and Hash password
	calculateHash := sha256.Sum256([]byte(password + salt))
	hash := hex.EncodeToString(calculateHash[:])

	// Store username, salt, and hash in db
	_, err = db.Exec(`INSERT INTO login (username, salt, hash) VALUES ($1, $2, $3)`, username, salt, hash)
	return nil
}

// SetPasswordNoHash Sets the password without hashing it
func SetPasswordNoHash(username string, passwordHash string, salt string, connectionStr PostgresConnection) error {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.SSL {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.Host, connectionStr.Port, connectionStr.User, connectionStr.Pass,
		connectionStr.Db, ssl)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return err
	}

	// Defer the disconnect
	defer func() {
		err := db.Close()
		if err != nil {
			panic(err)
		}
	}()

	_, err = db.Exec(`INSERT INTO login (username, salt, hash) VALUES ($1, $2, $3)`, username, salt, passwordHash)
	return nil
}

// CheckPassword Check if password is valid, returns (true, nil) if so
func CheckPassword(username string, password string, connectionStr PostgresConnection) (bool, error) {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.SSL {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.Host, connectionStr.Port, connectionStr.User, connectionStr.Pass,
		connectionStr.Db, ssl)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return false, err
	}

	// Defer the disconnect
	defer func() {
		err := db.Close()
		if err != nil {
			panic(err)
		}
	}()

	// Query the DB for salt and hash
	res := db.QueryRow(`SELECT salt, hash FROM login WHERE username=$1`, username)
	if res.Err() != nil {
		panic(err)
	}

	// Extract the salt and stored hash to variables
	var salt, storedHash string
	err = res.Scan(&salt, &storedHash)
	if err != nil {
		return false, err
	}

	newHash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(newHash[:]) == storedHash, nil
}

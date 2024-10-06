package postgres_credential_storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/lib/pq"
	"math/rand"
)

// Connection Details for postgres server
type postgresConnection struct {
	host string
	port int
	user string
	pass string
	db   string
	ssl  bool
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

// Set password in the database
func setPassword(username string, password string, connectionStr postgresConnection) error {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.ssl {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.host, connectionStr.port, connectionStr.user, connectionStr.pass,
		connectionStr.db, ssl)

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

// Sets the password without hashing it
func setPasswordNoHash(username string, passwordHash string, salt string, connectionStr postgresConnection) error {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.ssl {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.host, connectionStr.port, connectionStr.user, connectionStr.pass,
		connectionStr.db, ssl)

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

// Check if password is valid, returns (true, nil) if so
func checkPassword(username string, password string, connectionStr postgresConnection) (bool, error) {
	// Connect to the DB
	ssl := "disable"
	if connectionStr.ssl {
		ssl = "enable"
	}
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%v",
		connectionStr.host, connectionStr.port, connectionStr.user, connectionStr.pass,
		connectionStr.db, ssl)

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

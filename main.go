package postgres_credential_storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/lib/pq"
	"math/rand"
)

type postgresConnection struct {
	host string
	port int
	user string
	pass string
	db   string
	ssl  bool
}

func generateSalt() string {
	charSet := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&()*+,-./:;<=>?@[\\]^_{|}~"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet)-1)]
	}
	return string(b)
}

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

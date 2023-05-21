package userrepo

import (
	"database/sql"
	"log"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestDeleteSession(t *testing.T) {
	// Create a database connection
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	defer db.Close()

	// Create the user repository
	repo := &UserRepositorySqlite{db: db}

	_, err = repo.db.Exec(`
		CREATE TABLE sessions (
			token TEXT PRIMARY KEY,
			user_uuid TEXT NOT NULL,
			expiry_time TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("error creating sessions table: %v", err)
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE users (
  		user_uuid TEXT PRIMARY KEY,
  		username TEXT UNIQUE,
  		email TEXT UNIQUE,
  		active INTEGER,
  		status TEXT,
  		passwd TEXT,
  		first_name TEXT,
  		last_name TEXT,
  		role TEXT);
	`)

	if err != nil {
		t.Fatalf("error creating users table: %v", err)
	}

	// Create a new user
	userUUID := "123e4567-e89b-12d3-a456-426655440000"
	err = repo.Create(User{UserUUID: userUUID})
	if err != nil {
		t.Fatalf("error creating user: %v", err)
	}

	// Create a new session
	session, err := repo.CreateSession(userUUID)
	if err != nil {
		t.Fatalf("error creating session: %v", err)

	}

	// Validate the session was created
	row := db.QueryRow("SELECT token, user_uuid, expiry_time FROM sessions WHERE token = ?", session.Token)
	storedSession := &Session{}
	err = row.Scan(&storedSession.Token, &storedSession.UserUUID, &storedSession.ExpiryTime)
	if err != nil {
		t.Fatalf("error getting session record: %v", err)
	}

	// Delete the session
	err = repo.DeleteSession(session.Token)
	if err != nil {
		t.Fatalf("error deleting session: %v", err)
	}

	// Validate the session was deleted
	row = db.QueryRow("SELECT token, user_uuid, expiry_time FROM sessions WHERE token = ?", session.Token)
	storedSession = &Session{}
	err = row.Scan(&storedSession.Token, &storedSession.UserUUID, &storedSession.ExpiryTime)
	if err != sql.ErrNoRows {
		t.Fatalf("error getting session record: %v", err)
	}

}

func TestUserRepositorySqlite_Signup(t *testing.T) {

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	if err = db.Ping(); err != nil {
		t.Fatalf("error pinging database: %v", err)
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE users (
  		user_uuid TEXT PRIMARY KEY,
  		username TEXT UNIQUE,
  		email TEXT UNIQUE,
  		active INTEGER,
  		status TEXT,
  		passwd TEXT,
  		first_name TEXT,
  		last_name TEXT,
  		role TEXT);
	`)

	if err != nil {
		t.Fatalf("error creating users table: %v", err)
	}

	repo := &UserRepositorySqlite{db: db}

	// Test Signup with unique email
	user := User{
		UserUUID:  "123e4567-e89b-12d3-a456-426655440000",
		UserName:  "testuser",
		Email:     "testuser@example.com",
		Active:    true,
		Status:    "active",
		Passwd:    "s3cr3t",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}
	err = repo.Signup(user)
	if err != nil {
		t.Fatalf("error signing up user: %v", err)
	}
	retrievedUser, err := repo.GetByEmail(user.Email)
	if err != nil {
		t.Fatalf("error getting user by email: %v", err)
	}
	if retrievedUser.UserName != user.UserName {
		t.Errorf("expected username to be %q but got %q", user.UserName, retrievedUser.UserName)
	}

	// TODO: Add more test cases
}

func TestUserRepositorySqlite_CreateUser(t *testing.T) {
	repo, cleanup := newTestUserRepositorySqlite(t)
	defer cleanup()
	// Create users table
	_, err := repo.db.Exec(`
		CREATE TABLE users (
  		user_uuid TEXT PRIMARY KEY,
  		username TEXT UNIQUE,
  		email TEXT UNIQUE,
  		active INTEGER,
  		status TEXT,
  		passwd TEXT,
  		first_name TEXT,
  		last_name TEXT,
  		role TEXT);
	`)

	if err != nil {
		t.Fatalf("error creating users table: %v", err)
	}

	user := User{
		UserUUID:  "123e4567-e89b-12d3-a456-426655440000",
		UserName:  "testuser",
		Email:     "testuser@example.com",
		Active:    true,
		Status:    "active",
		Passwd:    "s3cr3t",
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}
	if err := repo.Create(user); err != nil {
		t.Fatalf("error creating user: %v", err)
	}

	retrievedUser, err := repo.GetByUUID(user.UserUUID)
	if err != nil {
		t.Fatalf("error getting user by UUID: %v", err)
	}
	if retrievedUser.UserName != user.UserName {
		t.Errorf("expected username to be %q but got %q", user.UserName, retrievedUser.UserName)
	}
}
func newTestUserRepositorySqlite(t *testing.T) (*UserRepositorySqlite, func()) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("error opening database: %v", err)
	}
	if err = db.Ping(); err != nil {
		t.Fatalf("error pinging database: %v", err)
	}
	repo := &UserRepositorySqlite{db: db}
	cleanup := func() {
		if err := repo.db.Close(); err != nil {
			t.Errorf("error closing database: %v", err)
		}
	}
	return repo, cleanup
}

func TestUserRepositorySqlite_ConfirmEmail(t *testing.T) {
	// Set up the database and repository
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error opening database connection: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
    CREATE TABLE email_confirmations (
        token TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        expiry_time DATETIME NOT NULL,
        confirmed BOOL NOT NULL)
	`)
	if err != nil {
		t.Fatalf("error creating email_confirmations table: %v", err)
	}

	repo := &UserRepositorySqlite{db}

	// Insert a new email confirmation record
	email := "test@example.com"

	expire := time.Now().UTC()
	expire = expire.Add(24 * time.Hour)
	confirmation, err := repo.CreateEmailConfirmation(email, expire)
	if err != nil {
		t.Fatalf("Error creating email confirmation record: %v", err)
	}
	log.Printf("Confirmation: %+v", confirmation)
	// Confirm the email
	err = repo.ConfirmEmail(confirmation.Token)
	if err != nil {
		t.Fatalf("Error confirming email: %v", err)
	}

	// Check that the email confirmation record was updated correctly
	emailConfirmation, err := repo.GetEmailConfirmation(confirmation.Token)
	if err != nil {
		t.Fatalf("Error getting email confirmation record: %v", err)
	}

	if !emailConfirmation.Confirmed {
		t.Fatalf("Email confirmation record not confirmed")
	}
}

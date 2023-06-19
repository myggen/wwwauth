package userrepo

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// Initial boilerplate generated with chatGPT .

type UserRepositorySqlite struct {
	db *sql.DB
}

// GetSession get a session by token
func (r *UserRepositorySqlite) GetSession(token string) (Session, error) {

	row := r.db.QueryRow("SELECT token, user_uuid, expiry_time FROM sessions WHERE token = ?", token)
	storedSession := Session{}
	err := row.Scan(&storedSession.Token, &storedSession.UserUUID, &storedSession.ExpiryTime)
	if err != nil && err != sql.ErrNoRows {
		return storedSession, err
	}
	return storedSession, nil
}

// DeleteSession deletes a session by token
func (r *UserRepositorySqlite) DeleteSession(token string) error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (r *UserRepositorySqlite) CreateSession(userUUID string) (Session, error) {
	// Generate a new token
	token, err := uuid.NewRandom()
	if err != nil {
		return Session{}, fmt.Errorf("error generating session token: %v", err)
	}

	// Calculate the expiry time'
	expiryTime := time.Now().Add(time.Hour * 15000)

	// Create a new session record
	session := Session{
		Token:      token.String(),
		UserUUID:   userUUID,
		ExpiryTime: expiryTime,
	}

	_, err = r.db.Exec("INSERT INTO sessions (token, user_uuid, expiry_time) VALUES (?, ?, ?)", session.Token, session.UserUUID, session.ExpiryTime)

	return session, err

}

func NewUserRepositorySqlite(dbPath string) (*UserRepositorySqlite, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("NewUserRepositorySqlite error param dbPath is blank ")
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database %s: %v", dbPath, err)
	}
	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("error pinging database %s: %v", dbPath, err)
	}
	return &UserRepositorySqlite{db: db}, nil
}

func (repo *UserRepositorySqlite) Create(user User) error {
	_, err := repo.db.Exec(
		"INSERT INTO users (user_uuid, username, email, active, status, passwd, first_name, last_name, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		user.UserUUID,
		user.UserName,
		user.Email,
		user.Active,
		user.Status,
		user.Passwd,
		user.FirstName,
		user.LastName,
		user.Role,
	)
	return err
}

func (repo *UserRepositorySqlite) Update(user User) error {
	_, err := repo.db.Exec(
		"UPDATE users SET username = ?, email = ?, active = ?, status = ?, passwd = ?, first_name = ?, last_name = ?, role = ? WHERE user_uuid = ?",
		user.UserName,
		user.Email,
		user.Active,
		user.Status,
		user.Passwd,
		user.FirstName,
		user.LastName,
		user.Role,
		user.UserUUID,
	)
	return err
}

func (repo *UserRepositorySqlite) Delete(userUUID string) error {
	_, err := repo.db.Exec(
		"DELETE FROM users WHERE user_uuid = ?",
		userUUID,
	)
	return err
}

func (repo *UserRepositorySqlite) GetByUUID(userUUID string) (User, error) {
	row := repo.db.QueryRow(
		"SELECT user_uuid, username, email, active, status, passwd, first_name, last_name, role FROM users WHERE user_uuid = ?",
		userUUID,
	)
	user := User{}
	err := rowscan(row, &user)
	return user, err

}

func (repo *UserRepositorySqlite) GetByEmail(email string) (User, error) {
	row := repo.db.QueryRow(
		"SELECT user_uuid, username, email, active, status, passwd, first_name, last_name, role FROM users WHERE email = ? COLLATE NOCASE",
		email,
	)
	user := User{}
	err := rowscan(row, &user)
	if err != nil && err != sql.ErrNoRows {
		return user, err
	}
	return user, nil
}

func rowscan(row *sql.Row, user *User) error {
	err := row.Scan(
		&user.UserUUID,
		&user.UserName,
		&user.Email,
		&user.Active,
		&user.Status,
		&user.Passwd,
		&user.FirstName,
		&user.LastName,
		&user.Role)

	return err
}
func (repo *UserRepositorySqlite) GetByUserName(userName string) (User, error) {
	row := repo.db.QueryRow(
		"SELECT user_uuid, username, email, active, status, passwd, first_name, last_name, role FROM users WHERE username = ? COLLATE NOCASE",
		userName,
	)
	user := User{}
	err := rowscan(row, &user)
	if err != nil && err != sql.ErrNoRows {
		return user, err
	}
	return user, nil

}

func (r *UserRepositorySqlite) Signup(user User) error {
	existingUser, err := r.GetByEmail(user.Email)
	if err != sql.ErrNoRows {
		return fmt.Errorf("Signup r.GetByEmail: %v", err)
	}
	if (existingUser != User{}) {
		log.Printf("UseR: %+v", existingUser)
		return errors.New("user with that email already exists")
	}
	return r.Create(user)
}

func (r *UserRepositorySqlite) GetEmailConfirmation(token string) (*EmailConfirmation, error) {
	// Query the email_confirmations table for the given token
	row := r.db.QueryRow("SELECT token, email, expiry_time, confirmed FROM email_confirmations WHERE token = ?", token)

	// Scan the result into a new EmailConfirmation struct
	emailConfirmation := &EmailConfirmation{}
	err := row.Scan(&emailConfirmation.Token, &emailConfirmation.Email, &emailConfirmation.ExpiryTime, &emailConfirmation.Confirmed)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("email confirmation token not found")
		}
		return nil, fmt.Errorf("error getting email confirmation record: %v", err)
	}

	return emailConfirmation, nil
}

// This method takes a token string, queries the email_confirmations table for
// the corresponding record, and scans the result into a new EmailConfirmation struct.
// If the token is not found, it returns an error. If there's any other error during
// the query, it returns an error as well.
func (r *UserRepositorySqlite) ConfirmEmail(token string) error {
	// Check if the token is valid and not expired
	emailConfirmation, err := r.GetEmailConfirmation(token)
	if err != nil {
		return fmt.Errorf("error confirming email: %v", err)
	}
	if emailConfirmation.Confirmed {
		return fmt.Errorf("email already confirmed")
	}
	if time.Now().After(emailConfirmation.ExpiryTime) {
		return fmt.Errorf("email confirmation token has expired")
	}

	// Mark the email as confirmed
	_, err = r.db.Exec("UPDATE email_confirmations SET confirmed = ? WHERE token = ?", true, token)
	if err != nil {
		return fmt.Errorf("error confirming email: %v", err)
	}
	return nil
}

// This method takes an email address and a token duration, generates a new email
// confirmation token, creates a new EmailConfirmation struct with the required
// fields, and inserts the record into the email_confirmations table.
// Add a new GetEmailConfirmation method to the `UserRepository
func (r *UserRepositorySqlite) CreateEmailConfirmation(email string, expiryTime time.Time) (EmailConfirmation, error) {
	// Generate a new token
	token, err := uuid.NewRandom()
	if err != nil {
		return EmailConfirmation{}, fmt.Errorf("error generating email confirmation token: %v", err)
	}

	// Create a new email confirmation record
	emailConfirmation := EmailConfirmation{
		Token:      token.String(),
		Email:      email,
		ExpiryTime: expiryTime,
		Confirmed:  false,
	}

	// Insert the new record into the email_confirmations table
	_, err = r.db.Exec(`
		INSERT INTO email_confirmations (token, email, expiry_time, confirmed)
		VALUES (?, ?, ?, ?)
	`, emailConfirmation.Token, emailConfirmation.Email, emailConfirmation.ExpiryTime, emailConfirmation.Confirmed)
	if err != nil {
		return EmailConfirmation{}, fmt.Errorf("error creating email confirmation record: %v", err)
	}

	return emailConfirmation, nil
}

func (r *UserRepositorySqlite) DeletePasswordResetRequest(token string) error {
	_, err := r.db.Exec("DELETE FROM password_reset_request WHERE token = ?", token)
	return err

}
func (r *UserRepositorySqlite) CreatePasswordResetRequest(email string, expiryTime time.Time) (PasswordResetRequest, error) {
	// Generate a new token
	token, err := uuid.NewRandom()
	if err != nil {
		return PasswordResetRequest{}, fmt.Errorf("error generating email confirmation token: %v", err)
	}

	passwordResetReq := PasswordResetRequest{
		Token:      token.String(),
		Email:      email,
		ExpiryTime: expiryTime,
		Confirmed:  false,
	}

	// Insert the new record into the email_confirmations table
	_, err = r.db.Exec(`
		INSERT INTO password_reset_request (token, email, expiry_time, confirmed)
		VALUES (?, ?, ?, ?)
	`, passwordResetReq.Token, passwordResetReq.Email, passwordResetReq.ExpiryTime, passwordResetReq.Confirmed)
	if err != nil {
		return PasswordResetRequest{}, fmt.Errorf("error creating password reset request record: %v", err)
	}

	return passwordResetReq, nil
}

func (r *UserRepositorySqlite) GetPasswordResetRequest(token string) (PasswordResetRequest, error) {
	// Query the email_confirmations table for the given token
	row := r.db.QueryRow("SELECT token, email, expiry_time, confirmed FROM password_reset_request WHERE token = ?", token)

	// Scan the result into a new PasswordResetRequest struct

	passwordResetReq := PasswordResetRequest{}
	err := row.Scan(&passwordResetReq.Token, &passwordResetReq.Email, &passwordResetReq.ExpiryTime, &passwordResetReq.Confirmed)
	if err != nil {
		if err == sql.ErrNoRows {
			return PasswordResetRequest{}, fmt.Errorf("email confirmation token not found")
		}
		return PasswordResetRequest{}, fmt.Errorf("error getting email confirmation record: %v", err)
	}

	return passwordResetReq, nil
}

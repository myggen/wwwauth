package userrepo

import "time"

// Session struct for storing session information in the database
type Session struct {
	Token      string
	UserUUID   string
	ExpiryTime time.Time
}

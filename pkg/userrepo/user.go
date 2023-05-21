package userrepo

import "time"

type User struct {
	UserUUID  string
	UserName  string
	Email     string
	Active    bool
	Status    string
	Passwd    string // Salted + bcrypted
	FirstName string
	LastName  string
	Role      string
}

type EmailConfirmation struct {
	Token      string
	Email      string
	ExpiryTime time.Time
	Confirmed  bool
}

type PasswordResetRequest struct {
	Token      string
	Email      string
	ExpiryTime time.Time
	Confirmed  bool
}

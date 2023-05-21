package userrepo

type UserRepository interface {
	Create(user *User) error
	Update(user *User) error
	Delete(userUUID string) error
	GetByUUID(userUUID string) (*User, error)
	GetByEmail(email string) (*User, error)
	List() ([]*User, error)
}

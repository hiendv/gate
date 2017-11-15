package fixtures

import (
	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

var errUserNotFound = errors.New("user not found")

// User is my user
type User struct {
	ID    string
	Email string
	Roles []string
}

// GetID returns user ID
func (u User) GetID() string {
	return u.ID
}

// GetEmail returns user Email
func (u User) GetEmail() string {
	return u.Email
}

// GetRoles returns user Roles
func (u User) GetRoles() []string {
	return u.Roles
}

// MyUserService is my user service
type MyUserService struct {
	records          []User
	GenerateMyUserID func() string
}

// NewMyUserService is the constructor for MyUserService
func NewMyUserService(records []User) *MyUserService {
	return &MyUserService{
		records,
		func() string {
			return RandomString(8)
		},
	}
}

// FindOneByID fetches the user with the given ID
func (service MyUserService) FindOneByID(ID string) (u gate.User, err error) {
	for _, record := range service.records {
		if record.ID == ID {
			u = record
			err = nil
			return
		}
	}
	err = errUserNotFound
	return
}

// FindOneByEmail fetches the user with the given email
func (service MyUserService) FindOneByEmail(email string) (u gate.User, err error) {
	for _, record := range service.records {
		if record.Email == email {
			u = record
			err = nil
			return
		}
	}
	err = errUserNotFound
	return
}

// FindOrCreateOneByEmail fetches the user with the given email or create a new one if the user doesn't exist
func (service *MyUserService) FindOrCreateOneByEmail(email string) (u gate.User, err error) {
	u, err = service.FindOneByEmail(email)
	if err == nil {
		return
	}

	if err != errUserNotFound {
		err = errors.New("something wrong")
		return
	}

	err = nil
	record := User{
		ID:    service.GenerateMyUserID(),
		Email: email,
	}
	service.records = append(service.records, record)
	u = record
	return
}

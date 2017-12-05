package fixtures

import (
	"strings"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

// EmailTriggeringDatabaseError should trigger database error
const EmailTriggeringDatabaseError string = "error@local"

var errUserNotFound = errors.New("user not found")

// User is my user
type User struct {
	ID    string
	Name  string
	Email string
	Roles []string
}

// GetID returns user ID
func (u User) GetID() string {
	return u.ID
}

// GetName returns user Name
func (u User) GetName() string {
	return u.Name
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
	domains          []string
	GenerateMyUserID func() string
}

// NewMyUserService is the constructor for MyUserService
func NewMyUserService(records []User, domains []string) *MyUserService {
	return &MyUserService{
		records,
		domains,
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
	if email == EmailTriggeringDatabaseError {
		err = errors.New("database error")
		return
	}

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

// CreateOneByAccount creates the user with the given email
func (service *MyUserService) CreateOneByAccount(account gate.Account) (u gate.User, err error) {
	email := account.GetEmail()
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		err = errors.New("invalid email")
		return
	}

	if !service.isDomainAllowed(parts[1]) {
		err = errors.New("forbidden email")
		return
	}

	record := User{
		ID:    service.GenerateMyUserID(),
		Name:  account.GetName(),
		Email: email,
	}
	service.records = append(service.records, record)
	u = record
	return
}

// IsErrNotFound determines whether the error is not found error or not
func (service *MyUserService) IsErrNotFound(err error) bool {
	return err == errUserNotFound
}

func (service *MyUserService) isDomainAllowed(domain string) bool {
	for _, d := range service.domains {
		if d == domain {
			return true
		}
	}

	return false
}

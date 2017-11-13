package password

import (
	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

var errUserNotFound = errors.New("user not found")

type user struct {
	id    string
	email string
	roles []string
}

func (u user) GetID() string {
	return u.id
}

func (u user) GetEmail() string {
	return u.email
}

func (u user) GetRoles() []string {
	return u.roles
}

type myUserService struct {
	records []user
}

var generateMyUserID = func() string {
	return randomString(8)
}

func (service myUserService) FindOneByID(id string) (u gate.User, err error) {
	for _, record := range service.records {
		if record.id == id {
			u = record
			err = nil
			return
		}
	}
	err = errUserNotFound
	return
}

func (service myUserService) findOneByEmail(email string) (u gate.User, err error) {
	for _, record := range service.records {
		if record.email == email {
			u = record
			err = nil
			return
		}
	}
	err = errUserNotFound
	return
}

func (service *myUserService) FindOrCreateOneByEmail(email string) (u gate.User, err error) {
	u, err = service.findOneByEmail(email)
	if err == nil {
		return
	}

	if err != errUserNotFound {
		err = errors.New("something wrong")
		return
	}

	err = nil
	record := user{
		id:    generateMyUserID(),
		email: email,
	}
	service.records = append(service.records, record)
	u = record
	return
}

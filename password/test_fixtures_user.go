package password

import (
	"errors"

	"github.com/hiendv/gate"
)

var errUserNotFound = errors.New("user not found")

type userActual struct {
	id       string
	username string
	password string
}

var actualUsers = []userActual{
	{id: randomString(8), username: "foo", password: "fooo"},
	{id: randomString(8), username: "bar", password: "barr"},
}

type user struct {
	id       string
	username string
	roles    []string
}

func (u user) GetID() string {
	return u.id
}

func (u user) GetUsername() string {
	return u.username
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

func (service myUserService) findOneByUsername(username string) (u gate.User, err error) {
	for _, record := range service.records {
		if record.username == username {
			u = record
			err = nil
			return
		}
	}
	err = errUserNotFound
	return
}

func (service *myUserService) FindOrCreateOneByUsername(username string) (u gate.User, err error) {
	u, err = service.findOneByUsername(username)
	if err == nil {
		return
	}

	if err != errUserNotFound {
		err = errors.New("something wrong")
		return
	}

	err = nil
	record := user{
		id:       generateMyUserID(),
		username: username,
	}
	service.records = append(service.records, record)
	u = record
	return
}

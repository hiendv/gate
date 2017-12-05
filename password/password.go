package password

import (
	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
)

// LoginFunc is the handler of password-based authentication
type LoginFunc func(driver Driver, email, password string) (gate.Account, error)

// Driver is password-based authentication
type Driver struct {
	dependency.Container
	config  Config
	handler LoginFunc
}

// LoginFuncStub is the stub for LoginFunc
var LoginFuncStub LoginFunc = func(Driver, string, string) (gate.Account, error) {
	return nil, nil
}

// New is the constructor for Driver
func New(config Config, handler LoginFunc, container dependency.Container) *Driver {
	var driver = &Driver{}

	driver.config = config

	if handler == nil {
		return nil
	}
	driver.handler = handler

	jwtConfig, err := gate.NewHMACJWTConfig("HS256", config.JWTSigningKey(), config.JWTExpiration(), config.JWTSkipClaimsValidation())
	if err != nil {
		return nil
	}
	container.SetJWTService(gate.NewJWTService(jwtConfig))
	container.SetMatcher(internal.NewMatcher())
	driver.Container = container

	return driver
}

// LoginURL returns the URL to the consent page
func (auth Driver) LoginURL(state string) (string, error) {
	return "", errors.New("the driver does not support login URL")
}

// Login resolves password-based authentication with the given handler and credentials
func (auth Driver) Login(credentials map[string]string) (user gate.User, err error) {
	email, ok := credentials["email"]
	if !ok {
		err = errors.New("missing email")
		return
	}

	password, ok := credentials["password"]
	if !ok {
		err = errors.New("missing password")
		return
	}

	person, err := auth.handler(auth, email, password)
	if err != nil {
		err = errors.Wrap(err, "could not login")
		return
	}

	service, err := auth.UserService()
	if err != nil {
		err = errors.Wrap(err, "invalid user service")
		return
	}

	if person.GetEmail() == "" {
		err = errors.New("missing account email")
		return
	}

	user, err = service.FindOneByEmail(person.GetEmail())
	if err == nil {
		return
	}

	if !service.IsErrNotFound(err) {
		err = errors.Wrap(err, "could not find the user")
		return
	}

	user, err = service.CreateOneByAccount(person)
	return
}

// IssueJWT issues and stores a JWT for a specific user
func (auth Driver) IssueJWT(user gate.User) (gate.JWT, error) {
	return gate.IssueJWT(auth, user)
}

// ParseJWT parses a JWT string to a JWT
func (auth Driver) ParseJWT(tokenString string) (gate.JWT, error) {
	return gate.ParseJWT(auth, tokenString)
}

// Authenticate performs the authentication using JWT
func (auth Driver) Authenticate(tokenString string) (gate.User, error) {
	return gate.Authenticate(auth, tokenString)
}

// GetUserFromJWT returns a user from a given JWT
func (auth Driver) GetUserFromJWT(token gate.JWT) (user gate.User, err error) {
	return gate.GetUserFromJWT(auth, token)
}

// Authorize performs the authorization when a given user takes an action on an object using RBAC
func (auth Driver) Authorize(user gate.User, action, object string) (err error) {
	return gate.Authorize(auth, user, action, object)
}

// GetUserAbilities returns a user's abilities
func (auth Driver) GetUserAbilities(user gate.User) (abilities []gate.UserAbility, err error) {
	return gate.GetUserAbilities(auth, user)
}

package password

import (
	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
)

// LoginFunc is the handler of password-based authentication
type LoginFunc func(email, password string) (gate.User, error)

// Driver is password-based authentication
type Driver struct {
	dependency.Container
	config  Config
	handler LoginFunc
}

// New is the constructor for Driver
func New(config Config, handler LoginFunc, container dependency.Container) *Driver {
	var driver = &Driver{}

	driver.config = config
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

	user, err = auth.handler(email, password)
	if err != nil {
		err = errors.Wrap(err, "could not login")
	}
	return
}

// IssueJWT issues and stores a JWT for a specific user
func (auth Driver) IssueJWT(user gate.User) (token gate.JWT, err error) {
	service, err := auth.JWTService()
	if err != nil {
		return
	}

	claims := service.NewClaims(user)
	token, err = service.Issue(claims)
	if err != nil {
		err = errors.Wrap(err, "could not issue JWT")
		return
	}

	err = auth.StoreJWT(token)
	if err != nil {
		err = errors.Wrap(err, "could not store JWT")
	}
	return
}

// StoreJWT stores a JWT using the given token service
func (auth Driver) StoreJWT(token gate.JWT) (err error) {
	service, err := auth.TokenService()
	if err != nil {
		return
	}

	return service.Store(token)
}

// ParseJWT parses a JWT string to a JWT
func (auth Driver) ParseJWT(tokenString string) (token gate.JWT, err error) {
	service, err := auth.JWTService()
	if err != nil {
		return
	}

	token, err = service.Parse(tokenString)
	if err != nil {
		err = errors.Wrap(err, "could not parse token")
	}

	return
}

// Authenticate performs the authentication using JWT
func (auth Driver) Authenticate(tokenString string) (user gate.User, err error) {
	token, err := auth.ParseJWT(tokenString)
	if err != nil {
		err = errors.Wrap(err, "could not parse the token")
		return
	}

	user, err = auth.GetUserFromJWT(token)
	if err != nil {
		err = errors.Wrap(err, "could not get the user")
	}
	return
}

// Authorize performs the authorization when a given user takes an action on an object using RBAC
func (auth Driver) Authorize(user gate.User, action, object string) (err error) {
	return gate.Authorize(auth, user, action, object)
}

// GetUserFromJWT returns a user from a given JWT
func (auth Driver) GetUserFromJWT(token gate.JWT) (user gate.User, err error) {
	service, err := auth.UserService()
	if err != nil {
		return
	}

	user, err = service.FindOneByID(token.UserID)
	if err != nil {
		err = errors.Wrap(err, "could not find the user with the given id")
	}
	return
}

// GetUserAbilities returns a user's abilities
func (auth Driver) GetUserAbilities(user gate.User) (abilities []gate.UserAbility, err error) {
	roleIDs := user.GetRoles()
	if len(roleIDs) == 0 {
		return
	}

	service, err := auth.RoleService()
	if err != nil {
		return
	}

	roles, err := service.FindByIDs(roleIDs)
	if err != nil {
		err = errors.Wrap(err, "could not fetch roles")
		return
	}

	for _, role := range roles {
		abilities = append(abilities, role.GetAbilities()...)
	}
	return
}

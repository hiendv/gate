package gate

import (
	"github.com/hiendv/gate/internal"
)

// Auth is the common interface for authentication and authorization. E.g. PasswordBased, OAuth, etc.
type Auth interface {
	UserService() (UserService, error)
	RoleService() (RoleService, error)
	TokenService() (TokenService, error)
	JWTService() (*JWTService, error)
	Matcher() (internal.Matcher, error)

	Login(map[string]string) (User, error)
	LoginURL(string) (string, error)

	IssueJWT(User) (JWT, error)
	ParseJWT(string) (JWT, error)
	StoreJWT(JWT) error

	Authenticate(string) (User, error)
	Authorize(User, string, string) error

	GetUserFromJWT(JWT) (User, error)
	GetUserAbilities(User) ([]UserAbility, error)
}

// UserService is the contract which offers queries on the user entity
type UserService interface {
	FindOneByID(string) (User, error)
	FindOrCreateOneByEmail(string) (User, error)
}

// RoleService is the contract which offers queries on the role entity
type RoleService interface {
	FindByIDs([]string) ([]Role, error)
}

// TokenService is the contract which offers queries on the token entity
type TokenService interface {
	FindOneByID(string) (JWT, error)
	Store(JWT) error
}

// HasEmail is the contract for user service entity
type HasEmail interface {
	GetEmail() string
}

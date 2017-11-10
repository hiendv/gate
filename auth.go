package gate

import (
	"time"
)

// Auth is the common interface for authentication and authorization. E.g. PasswordBased, OAuth, etc.
type Auth interface {
	GetConfig() Config

	UserService() (UserService, error)
	RoleService() (RoleService, error)
	TokenService() (TokenService, error)
	JWTService() (JWTService, error)
	Matcher() (Matcher, error)

	Login(map[string]string) (User, error)

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

// Config is the configuration for Auth
type Config struct {
	jwtSigningKey           interface{}
	jwtVerifyingKey         interface{}
	jwtExpiration           time.Duration
	jwtSkipClaimsValidation bool
}

// JWTSigningKey is the setter for JWT signing key configuration
func (config Config) JWTSigningKey() interface{} {
	return config.jwtSigningKey
}

// JWTVerifyingKey is the setter for JWT verifying key configuration
func (config Config) JWTVerifyingKey() interface{} {
	return config.jwtVerifyingKey
}

// JWTExpiration is the setter for JWT expiration configuration
func (config Config) JWTExpiration() time.Duration {
	return config.jwtExpiration
}

// JWTSkipClaimsValidation is the setter for JWT claims validation skip configuration
func (config Config) JWTSkipClaimsValidation() bool {
	return config.jwtSkipClaimsValidation
}

// NewConfig is the constructor for Config
func NewConfig(jwtSigningKey, jwtVerifyingKey interface{}, jwtExpiration time.Duration, jwtSkipClaimsValidation bool) Config {
	return Config{jwtSigningKey, jwtVerifyingKey, jwtExpiration, jwtSkipClaimsValidation}
}

// Dependencies is the servicer container for Auth
type Dependencies struct {
	userService  UserService
	roleService  RoleService
	tokenService TokenService
	jwtService   JWTService
	matcher      Matcher
}

// UserService is the getter for user service
func (dependencies Dependencies) UserService() UserService {
	return dependencies.userService
}

// RoleService is the getter for role service
func (dependencies Dependencies) RoleService() RoleService {
	return dependencies.roleService
}

// TokenService is the getter for token service
func (dependencies Dependencies) TokenService() TokenService {
	return dependencies.tokenService
}

// JWTService is the getter for JWT service
func (dependencies Dependencies) JWTService() JWTService {
	return dependencies.jwtService
}

// Matcher is the getter for matcher
func (dependencies Dependencies) Matcher() Matcher {
	return dependencies.matcher
}

// SetJWTService is the setter for JWT service
func (dependencies *Dependencies) SetJWTService(service JWTService) {
	dependencies.jwtService = service
}

// SetMatcher is the setter for matcher
func (dependencies *Dependencies) SetMatcher(matcher Matcher) {
	dependencies.matcher = matcher
}

// NewDependencies is the constructor for Dependencies
func NewDependencies(users UserService, tokens TokenService, roles RoleService) *Dependencies {
	return &Dependencies{userService: users, tokenService: tokens, roleService: roles}
}

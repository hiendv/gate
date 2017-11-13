package gate

import (
	"github.com/hiendv/gate/internal"
)

// Dependencies is the servicer container for Auth
type Dependencies struct {
	userService  UserService
	roleService  RoleService
	tokenService TokenService
	jwtService   JWTService
	matcher      internal.Matcher
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
func (dependencies Dependencies) Matcher() internal.Matcher {
	return dependencies.matcher
}

// SetJWTService is the setter for JWT service
func (dependencies *Dependencies) SetJWTService(service JWTService) {
	dependencies.jwtService = service
}

// SetMatcher is the setter for matcher
func (dependencies *Dependencies) SetMatcher(matcher internal.Matcher) {
	dependencies.matcher = matcher
}

// NewDependencies is the constructor for Dependencies
func NewDependencies(users UserService, tokens TokenService, roles RoleService) *Dependencies {
	return &Dependencies{userService: users, tokenService: tokens, roleService: roles}
}

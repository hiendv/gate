package dependency

import (
	"github.com/hiendv/gate"
	"github.com/hiendv/gate/internal"
)

// Services is the servicer container for Auth
type Services struct {
	userService  gate.UserService
	roleService  gate.RoleService
	tokenService gate.TokenService
	jwtService   gate.JWTService
	matcher      internal.Matcher
}

// UserService is the getter for user service
func (services Services) UserService() gate.UserService {
	return services.userService
}

// RoleService is the getter for role service
func (services Services) RoleService() gate.RoleService {
	return services.roleService
}

// TokenService is the getter for token service
func (services Services) TokenService() gate.TokenService {
	return services.tokenService
}

// JWTService is the getter for JWT service
func (services Services) JWTService() gate.JWTService {
	return services.jwtService
}

// Matcher is the getter for matcher
func (services Services) Matcher() internal.Matcher {
	return services.matcher
}

// SetJWTService is the setter for JWT service
func (services *Services) SetJWTService(service gate.JWTService) {
	services.jwtService = service
}

// SetMatcher is the setter for matcher
func (services *Services) SetMatcher(matcher internal.Matcher) {
	services.matcher = matcher
}

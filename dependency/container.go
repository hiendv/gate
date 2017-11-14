package dependency

import (
	"github.com/hiendv/gate"
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
)

// Container is the service container
type Container struct {
	services *Services
}

// UserService returns user service from the services or throws an error if the service is invalid
func (container Container) UserService() (gate.UserService, error) {
	if container.services == nil {
		return nil, errors.New("invalid services")
	}

	if container.services.UserService() == nil {
		return nil, errors.New("invalid user service")
	}

	return container.services.UserService(), nil
}

// RoleService returns role service from the services or throws an error if the service is invalid
func (container Container) RoleService() (gate.RoleService, error) {
	if container.services == nil {
		return nil, errors.New("invalid services")
	}

	if container.services.RoleService() == nil {
		return nil, errors.New("invalid role service")
	}

	return container.services.RoleService(), nil
}

// TokenService returns token service from the services or throws an error if the service is invalid
func (container Container) TokenService() (gate.TokenService, error) {
	if container.services == nil {
		return nil, errors.New("invalid services")
	}

	if container.services.TokenService() == nil {
		return nil, errors.New("invalid token service")
	}

	return container.services.TokenService(), nil
}

// JWTService returns JWT service from the services or throws an error if the service is invalid
func (container Container) JWTService() (gate.JWTService, error) {
	if container.services == nil {
		return gate.JWTService{}, errors.New("invalid services")
	}

	return container.services.JWTService(), nil
}

// SetJWTService is the setter for JWT service
func (container Container) SetJWTService(service gate.JWTService) {
	container.services.SetJWTService(service)
}

// Matcher returns Matcher instance from the services or throws an error if the instance is invalid
func (container Container) Matcher() (internal.Matcher, error) {
	if container.services == nil {
		return internal.Matcher{}, errors.New("invalid services")
	}

	return container.services.Matcher(), nil
}

// SetMatcher is the setter for matcher
func (container Container) SetMatcher(matcher internal.Matcher) {
	container.services.SetMatcher(matcher)
}

// NewContainer is the constructor for container
func NewContainer(users gate.UserService, tokens gate.TokenService, roles gate.RoleService) Container {
	return Container{
		&Services{userService: users, tokenService: tokens, roleService: roles},
	}
}

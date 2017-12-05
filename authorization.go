package gate

import (
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
)

var (
	// ErrForbidden is thrown when an user is forbidden to take an action on an object
	ErrForbidden = errors.New("forbidden")

	// ErrNoAbilities is thrown when an user has no abilities
	ErrNoAbilities = errors.New("there is no abilities")
)

// Authorize performs the authorization when a given user takes an action on an object using RBAC
func Authorize(auth Auth, user User, action, object string) (err error) {
	abilities, err := auth.GetUserAbilities(user)
	if err != nil {
		err = errors.Wrap(err, "could not get the abilities")
		return
	}

	if len(abilities) == 0 {
		err = ErrNoAbilities
		return
	}

	if !authorizationCheck(auth, action, object, abilities) {
		err = ErrForbidden
	}
	return
}

// GetUserAbilities returns a user's abilities
func GetUserAbilities(auth Auth, user User) (abilities []UserAbility, err error) {
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

func authorizationCheck(auth Auth, action, object string, abilities []UserAbility) bool {
	matcher, err := auth.Matcher()
	if err != nil {
		return false
	}

	for _, ability := range abilities {
		matched := internal.AuthorizationCheck(matcher, action, object, ability)
		if matched {
			return true
		}
	}

	return false
}

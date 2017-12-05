package gate

import (
	"github.com/pkg/errors"
)

// Authenticate performs the authentication using JWT
func Authenticate(auth Auth, tokenString string) (user User, err error) {
	token, err := auth.ParseJWT(tokenString)
	if err != nil {
		err = errors.Wrap(err, "could not parse the token")
		return
	}

	user, err = auth.GetUserFromJWT(token)
	if err != nil {
		err = errors.Wrap(err, "could not get the user")
		return
	}
	return
}

// GetUserFromJWT returns a user from a given JWT
func GetUserFromJWT(auth Auth, token JWT) (user User, err error) {
	service, err := auth.UserService()
	if err != nil {
		return
	}

	user, err = service.FindOneByID(token.UserID)
	if err != nil {
		err = errors.Wrap(err, "could not find the user with the given id")
		return
	}
	return
}

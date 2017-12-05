package gate

import (
	"github.com/pkg/errors"
)

// IssueJWT issues and stores a JWT for a specific user
func IssueJWT(auth Auth, user User) (token JWT, err error) {
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

	err = StoreJWT(auth, token)
	if err != nil {
		err = errors.Wrap(err, "could not store JWT")
		return
	}
	return
}

// StoreJWT stores a JWT using the given token service
func StoreJWT(auth Auth, token JWT) (err error) {
	service, err := auth.TokenService()
	if err != nil {
		return
	}

	return service.Store(token)
}

// ParseJWT parses a JWT string to a JWT
func ParseJWT(auth Auth, tokenString string) (token JWT, err error) {
	service, err := auth.JWTService()
	if err != nil {
		return
	}

	token, err = service.Parse(tokenString)
	if err != nil {
		err = errors.Wrap(err, "could not parse token")
		return
	}

	return
}

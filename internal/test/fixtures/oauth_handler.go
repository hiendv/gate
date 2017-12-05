package fixtures

import (
	"github.com/hiendv/gate"
	"github.com/hiendv/gate/oauth"
	"github.com/pkg/errors"
)

// CodeAndStateOAuthHandler is the stub for Handler
var CodeAndStateOAuthHandler oauth.Handler = func(user gate.Account) oauth.LoginFunc {
	return func(driver oauth.Driver, code, state string) (gate.Account, error) {
		if code == "code" && state == "state" {
			return oauth.GoogleUser{Email: "email@gmail.com", EmailVerified: true}, nil
		}

		return nil, errors.New("invalid credentials")
	}
}

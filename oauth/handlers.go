package oauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

// GoogleUser is the user from Google API
type GoogleUser struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// GetEmail returns user's email
func (user GoogleUser) GetEmail() string {
	if !user.EmailVerified {
		return ""
	}

	return user.Email
}

// GoogleStatelessHandler is the stateless login handler using Google API
var GoogleStatelessHandler LoginFunc = func(driver Driver, code, state string) (account gate.HasEmail, err error) {
	// State is ignored

	token, err := driver.provider.Exchange(context.TODO(), code)
	if err != nil {
		return
	}

	client := driver.provider.Client(context.TODO(), token)
	if client == nil {
		err = errors.New("invalid API client")
		return
	}

	response, err := client.Get(driver.config.UserAPI)
	if err != nil {
		return
	}
	if response == nil {
		err = errors.New("invalid API response")
		return
	}
	defer func(response *http.Response) {
		e := response.Body.Close()
		if e == nil {
			return
		}

		// TODO
	}(response)

	var user GoogleUser
	err = json.NewDecoder(response.Body).Decode(&user)
	if err != nil {
		return
	}

	account = user
	return
}

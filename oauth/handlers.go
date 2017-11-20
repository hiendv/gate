package oauth

import (
	"encoding/json"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type GoogleUser struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (user GoogleUser) GetEmail() string {
	if !user.EmailVerified {
		return ""
	}

	return user.Email
}

var GoogleStatelessHandler LoginFunc = func(driver Driver, code, state string) (account gate.HasEmail, err error) {
	// State is ignored

	token, err := driver.provider.Exchange(oauth2.NoContext, code)
	if err != nil {
		return
	}

	client := driver.provider.Client(oauth2.NoContext, token)
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
	defer response.Body.Close()

	var user GoogleUser
	err = json.NewDecoder(response.Body).Decode(&user)
	if err != nil {
		return
	}

	account = user
	return
}

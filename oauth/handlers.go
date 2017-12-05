package oauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

// Handler is the login handler
type Handler func(user gate.Account) LoginFunc

// HandlerStub is the stub for Handler
var HandlerStub Handler = func(user gate.Account) LoginFunc {
	return func(driver Driver, code, state string) (gate.Account, error) {
		return nil, nil
	}
}

// StatelessHandler is the stateless handler
func StatelessHandler(user gate.Account) LoginFunc {
	return func(driver Driver, code, state string) (account gate.Account, err error) {
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

		err = json.NewDecoder(response.Body).Decode(user)
		if err != nil {
			return
		}

		account = user
		return
	}
}

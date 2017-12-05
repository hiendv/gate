package fixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type contextKey string

const noResponseKey contextKey = "no-response"
const malformedResponseKey contextKey = "malformed-response"

// OAuthClient is the mocking HTTP client for OAuth driver
type OAuthClient struct {
	ctx       context.Context
	token     *oauth2.Token
	responses map[string]gate.Account
}

// Get makes a GET request with the given URL
func (client OAuthClient) Get(url string) (resp *http.Response, err error) {
	if noResponse, ok := client.ctx.Value(noResponseKey).(bool); ok && noResponse {
		return nil, nil
	}

	if client.token == nil || client.token.AccessToken == "" {
		err = errors.New("invalid token")
		return
	}

	if malformedResponse, ok := client.ctx.Value(malformedResponseKey).(bool); ok && malformedResponse {
		return &http.Response{
			Body: ioutil.NopCloser(bytes.NewBufferString("malformed")),
		}, nil
	}

	user := client.responses[client.token.AccessToken]

	result, err := json.Marshal(user)
	if err != nil {
		return
	}

	return &http.Response{
		Body: ioutil.NopCloser(bytes.NewBuffer(result)),
	}, nil
}

// OAuthProvider is the mocking provider for OAuth driver
type OAuthProvider struct {
	Responses map[string]gate.Account
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
func (config OAuthProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return ""
}

// Exchange converts an authorization code into a token
func (config OAuthProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if code == "" {
		return nil, nil
	}

	token := &oauth2.Token{}
	token.AccessToken = fmt.Sprintf("%s-token", code)

	return token, nil
}

// Client returns an HTTP client using the provided token
func (config OAuthProvider) Client(ctx context.Context, token *oauth2.Token) internal.HTTPClient {
	return OAuthClient{ctx, token, config.Responses}
}

// BadOAuthProvider is the mocking provider with no client for OAuth driver
type BadOAuthProvider struct {
	NoClient          bool
	NoResponse        bool
	MalformedResponse bool
	OAuthProvider
}

// Client returns an HTTP client using the provided token
func (config BadOAuthProvider) Client(ctx context.Context, token *oauth2.Token) internal.HTTPClient {
	if config.NoClient {
		return nil
	}

	if config.NoResponse {
		ctx = context.WithValue(ctx, noResponseKey, true)
	}

	if config.MalformedResponse {
		ctx = context.WithValue(ctx, malformedResponseKey, true)
	}

	return config.OAuthProvider.Client(ctx, token)
}

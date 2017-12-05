package oauth

import (
	"context"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// LoginFunc is the handler of OAuth authentication
type LoginFunc func(driver Driver, code, state string) (gate.Account, error)

// Driver is OAuth authentication
type Driver struct {
	dependency.Container
	config   Config
	handler  LoginFunc
	provider Provider
}

// Provider is the OAuth provider
type Provider interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	Client(ctx context.Context, t *oauth2.Token) internal.HTTPClient
}

// DefaultProvider is the default OAuth provider
type DefaultProvider struct {
	config *oauth2.Config
}

// AuthCodeURL returns a URL to OAuth 2.0 provider's consent page
func (provider DefaultProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return provider.config.AuthCodeURL(state, opts...)
}

// Exchange converts an authorization code into a token
func (provider DefaultProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return provider.config.Exchange(ctx, code)
}

// Client returns an HTTP client using the provided token
func (provider DefaultProvider) Client(ctx context.Context, t *oauth2.Token) internal.HTTPClient {
	return provider.config.Client(ctx, t)
}

// New is the constructor for Driver
func New(config Config, handler Handler, container dependency.Container) *Driver {
	var driver = &Driver{}

	driver.config = config
	driver.SetProvider(DefaultProvider{
		&oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			RedirectURL:  config.RedirectURI,
			Scopes:       config.Scopes,
			Endpoint:     config.Endpoint,
		},
	})

	if handler == nil {
		return nil
	}
	driver.handler = handler(config.Account)
	if driver.handler == nil {
		return nil
	}

	jwtConfig, err := gate.NewHMACJWTConfig("HS256", config.JWTSigningKey(), config.JWTExpiration(), config.JWTSkipClaimsValidation())
	if err != nil {
		return nil
	}

	container.SetJWTService(gate.NewJWTService(jwtConfig))
	container.SetMatcher(internal.NewMatcher())
	driver.Container = container

	return driver
}

// GetProvider is the getter for OAuth provider
func (auth Driver) GetProvider() Provider {
	return auth.provider
}

// SetProvider is the setter for OAuth provider
func (auth *Driver) SetProvider(provider Provider) {
	auth.provider = provider
}

// LoginURL returns the URL to the consent page
func (auth Driver) LoginURL(state string) (string, error) {
	if auth.provider == nil {
		return "", errors.New("invalid oauth configuration")
	}

	return auth.provider.AuthCodeURL(state), nil
}

// Login resolves OAuth authentication with the given handler and credentials
func (auth Driver) Login(credentials map[string]string) (user gate.User, err error) {
	code, ok := credentials["code"]
	if !ok {
		err = errors.New("missing code")
		return
	}

	// state is optional because of stateless cases
	person, err := auth.handler(auth, code, credentials["state"])
	if err != nil {
		err = errors.Wrap(err, "could not login")
		return
	}

	service, err := auth.UserService()
	if err != nil {
		err = errors.Wrap(err, "invalid user service")
		return
	}

	if person.GetEmail() == "" {
		err = errors.New("missing account email")
		return
	}

	user, err = service.FindOneByEmail(person.GetEmail())
	if err == nil {
		return
	}

	if !service.IsErrNotFound(err) {
		err = errors.Wrap(err, "could not find the user")
		return
	}

	user, err = service.CreateOneByAccount(person)
	return
}

// IssueJWT issues and stores a JWT for a specific user
func (auth Driver) IssueJWT(user gate.User) (gate.JWT, error) {
	return gate.IssueJWT(auth, user)
}

// ParseJWT parses a JWT string to a JWT
func (auth Driver) ParseJWT(tokenString string) (gate.JWT, error) {
	return gate.ParseJWT(auth, tokenString)
}

// Authenticate performs the authentication using JWT
func (auth Driver) Authenticate(tokenString string) (gate.User, error) {
	return gate.Authenticate(auth, tokenString)
}

// GetUserFromJWT returns a user from a given JWT
func (auth Driver) GetUserFromJWT(token gate.JWT) (user gate.User, err error) {
	return gate.GetUserFromJWT(auth, token)
}

// Authorize performs the authorization when a given user takes an action on an object using RBAC
func (auth Driver) Authorize(user gate.User, action, object string) (err error) {
	return gate.Authorize(auth, user, action, object)
}

// GetUserAbilities returns a user's abilities
func (auth Driver) GetUserAbilities(user gate.User) (abilities []gate.UserAbility, err error) {
	return gate.GetUserAbilities(auth, user)
}

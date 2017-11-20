package oauth

import (
	"github.com/hiendv/gate"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

// Config is the configuration for OAuth authentication
type Config struct {
	gate.Config
	ClientID     string
	ClientSecret string
	Scopes       []string
	Endpoint     oauth2.Endpoint
	RedirectURI  string
	UserAPI      string
}

// NewGoogleConfig is the constructor for OAuth configuration using Google API
func NewGoogleConfig(base gate.Config, id, secret, redirectURI string) Config {
	return Config{
		base,
		id,
		secret,
		[]string{"https://www.googleapis.com/auth/userinfo.email"},
		google.Endpoint,
		redirectURI,
		"https://www.googleapis.com/oauth2/v3/userinfo",
	}
}

// NewFacebookConfig is the constructor for OAuth configuration using Facebook API
func NewFacebookConfig(base gate.Config, id, secret, redirectURI string) Config {
	return Config{
		base,
		id,
		secret,
		[]string{"email"},
		facebook.Endpoint,
		redirectURI,
		"https://graph.facebook.com/v2.11/me?fields=id,name,email",
	}
}

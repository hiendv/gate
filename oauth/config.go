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
	Account      gate.Account
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
		&GoogleUser{},
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
		&FacebookUser{},
	}
}

// GoogleUser is the user from Google API
type GoogleUser struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// GetName returns user's name
func (user GoogleUser) GetName() string {
	return user.Name
}

// GetEmail returns user's email
func (user GoogleUser) GetEmail() string {
	if !user.EmailVerified {
		return ""
	}

	return user.Email
}

// FacebookUser is the user from Google API
type FacebookUser struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"true"`
}

// GetName returns user's name
func (user FacebookUser) GetName() string {
	return user.Name
}

// GetEmail returns user's email
func (user FacebookUser) GetEmail() string {
	if !user.EmailVerified {
		return ""
	}

	return user.Email
}

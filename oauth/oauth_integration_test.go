package oauth_test

import (
	"os"
	"testing"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal/test"
	"github.com/hiendv/gate/internal/test/fixtures"
	"github.com/hiendv/gate/oauth"
)

var (
	auth         gate.Auth
	driver       *oauth.Driver
	userService  *fixtures.MyUserService
	tokenService *fixtures.MyTokenService
	roleService  *fixtures.MyRoleService
)

func TestMain(m *testing.M) {
	roles := []fixtures.Role{
		{
			ID: fixtures.RandomString(8),
			Abilities: []fixtures.Ability{
				{Action: "GET", Object: "/api/v1/*"},
				{Action: "POST", Object: "/api/v1/users*"},
			},
		},
		{
			ID: fixtures.RandomString(8),
			Abilities: []fixtures.Ability{
				{Action: "GET", Object: "*"},
			},
		},
		{
			ID: fixtures.RandomString(8),
			Abilities: []fixtures.Ability{
				{Action: "POST", Object: "/api/v1/posts*"},
			},
		},
	}

	users := []fixtures.User{
		{
			ID:    fixtures.RandomString(8),
			Email: "foo@local",
			Roles: []string{
				roles[0].ID,
				roles[1].ID,
			},
		},
		{
			ID:    fixtures.RandomString(8),
			Email: "bar@local",
			Roles: []string{},
		},
		{
			ID:    fixtures.RandomString(8),
			Email: "nobody@local",
			Roles: []string{},
		},
	}

	roleService = fixtures.NewMyRoleService(roles)
	userService = fixtures.NewMyUserService(users)
	tokenService = fixtures.NewMyTokenService(nil)

	driver = oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"client-id",
			"client-secret",
			"http://localhost:8080",
		),
		oauth.GoogleStatelessHandler,
		dependency.NewContainer(userService, tokenService, roleService),
	)

	auth = driver
	if auth == nil {
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestOAuthWithBadProvider(t *testing.T) {
	t.Run("login", func(t *testing.T) {
		provider := driver.GetProvider()
		defer driver.SetProvider(provider)

		t.Run("no client", func(t *testing.T) {
			driver.SetProvider(fixtures.BadOAuthProvider{NoClient: true})
			_, err := auth.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertErr(t, err, "no client")
		})

		t.Run("no response", func(t *testing.T) {
			driver.SetProvider(fixtures.BadOAuthProvider{NoResponse: true})
			_, err := auth.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertErr(t, err, "no response")
		})

		t.Run("malformed response", func(t *testing.T) {
			driver.SetProvider(fixtures.BadOAuthProvider{MalformedResponse: true, OAuthProvider: fixtures.OAuthProvider{}})
			_, err := auth.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertErr(t, err, "malformed response")
		})
	})
}

func TestOAuthWithDefaultProvider(t *testing.T) {
	t.Run("login url", func(t *testing.T) {
		_, err := auth.LoginURL("state")
		test.AssertOK(t, err, "supported login URL")

		t.Run("without provider", func(t *testing.T) {
			provider := driver.GetProvider()
			defer driver.SetProvider(provider)

			driver.SetProvider(nil)

			_, err := auth.LoginURL("state")
			test.AssertErr(t, err, "invalid provider")
		})
	})

	t.Run("login", func(t *testing.T) {
		t.Run("invalid credentials", func(t *testing.T) {
			_, err := auth.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertErr(t, err, "invalid credentials")
		})
	})
}

func TestOAuthWithMockedProvider(t *testing.T) {
	provider := driver.GetProvider()
	defer driver.SetProvider(provider)

	driver.SetProvider(fixtures.OAuthProvider{
		map[string]gate.HasEmail{
			"code-token": oauth.GoogleUser{
				Email:         "foo@local",
				EmailVerified: true,
			},
			"code2-token": oauth.GoogleUser{
				Email:         "foo@local",
				EmailVerified: true,
			},
			"code3-token": oauth.GoogleUser{
				Email:         "bar@local",
				EmailVerified: false,
			},
			"code4-token": oauth.GoogleUser{
				Email:         "qux@local",
				EmailVerified: true,
			},
		},
	})

	t.Run("login", func(t *testing.T) {
		t.Run("valid credentials", func(t *testing.T) {
			firstUser, err := auth.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertOK(t, err, "valid credentials")

			secondUser, err := auth.Login(map[string]string{"code": "code2", "state": "state"})
			test.AssertOK(t, err, "valid credentials")

			if firstUser.GetID() != secondUser.GetID() {
				t.Errorf("ids should be equal: %v - %v", firstUser.GetID(), secondUser.GetID())
			}

			_, err = auth.Login(map[string]string{"code": "code3"})
			test.AssertErr(t, err, "unverified email")

			_, err = auth.Login(map[string]string{"code": "code4"})
			test.AssertErr(t, err, "non-existing user")
		})

		t.Run("invalid credentials", func(t *testing.T) {
			_, err := auth.Login(map[string]string{"state": "barr"})
			test.AssertErr(t, err, "missing code")

			_, err = auth.Login(map[string]string{"code": "", "state": ""})
			test.AssertErr(t, err, "invalid credentials")
		})
	})
}

func TestOAuthJWT(t *testing.T) {
	t.Run("issue", func(t *testing.T) {
		t.Run("with a valid jwt service", func(t *testing.T) {
			user, err := userService.FindOneByEmail("foo@local")
			test.AssertOK(t, err, "existing user")

			token, err := auth.IssueJWT(user)
			test.AssertOK(t, err, "valid user")

			if user.GetID() != token.UserID {
				t.Fatalf("id mismatch: %s - %s", user.GetID(), token.UserID)
			}

			_, err = tokenService.FindOneByID(token.ID)
			test.AssertOK(t, err, "existing token")
		})
	})

	t.Run("validate", func(t *testing.T) {
		t.Run("parse", func(t *testing.T) {
			_, err := auth.ParseJWT("invalid JWT")
			test.AssertErr(t, err, "invalid token")
		})

		t.Run("parse and fetch user", func(t *testing.T) {
			user, err := userService.FindOneByEmail("foo@local")
			test.AssertOK(t, err, "existing user")

			token, err := auth.IssueJWT(user)
			test.AssertOK(t, err, "valid user")

			tokenString, err := auth.ParseJWT(token.Value)
			test.AssertOK(t, err, "valid token")

			_, err = auth.GetUserFromJWT(tokenString)
			test.AssertOK(t, err, "existing user")
		})

		t.Run("authenticate", func(t *testing.T) {
			user, err := userService.FindOneByEmail("foo@local")
			test.AssertOK(t, err, "existing user")

			t.Run("invalid JWT", func(t *testing.T) {
				_, err := auth.Authenticate("invalid JWT")
				test.AssertErr(t, err, "invalid token")
			})

			t.Run("invalid user", func(t *testing.T) {
				token, err := auth.IssueJWT(fixtures.User{ID: "another-id", Email: user.GetEmail(), Roles: user.GetRoles()})
				test.AssertOK(t, err, "valid user")

				_, err = auth.Authenticate(token.Value)
				test.AssertErr(t, err, "non-existing user")
			})

			t.Run("valid user", func(t *testing.T) {
				token, err := auth.IssueJWT(user)
				test.AssertOK(t, err, "valid user")

				_, err = auth.Authenticate(token.Value)
				test.AssertOK(t, err, "existing user")
			})
		})

		t.Run("authorize", func(t *testing.T) {
			t.Run("for a normal user", func(t *testing.T) {
				user, err := userService.FindOneByEmail("foo@local")
				test.AssertOK(t, err, "existing user")

				token, err := auth.IssueJWT(user)
				test.AssertOK(t, err, "valid user")

				user, err = auth.Authenticate(token.Value)
				test.AssertOK(t, err, "existing user")

				err = auth.Authorize(user, "GET", "/api")
				test.AssertOK(t, err, "valid abilities")

				err = auth.Authorize(user, "GET", "/api/v1/users")
				test.AssertOK(t, err, "valid abilities")

				err = auth.Authorize(user, "GET", "/api/v1/posts")
				test.AssertOK(t, err, "valid abilities")

				err = auth.Authorize(user, "POST", "/api/v1/posts")
				test.AssertErr(t, err, "invalid abilities")
			})

			t.Run("for a user with no roles", func(t *testing.T) {
				user, err := userService.FindOneByEmail("nobody@local")
				test.AssertOK(t, err, "existing user")

				token, err := auth.IssueJWT(user)
				test.AssertOK(t, err, "valid user")

				user, err = auth.Authenticate(token.Value)
				test.AssertOK(t, err, "existing user")

				err = auth.Authorize(user, "GET", "/api")
				test.AssertErr(t, err, "user has no roles")
			})
		})
	})
}

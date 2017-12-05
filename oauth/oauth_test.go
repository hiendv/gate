package oauth_test

import (
	"testing"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal/test"
	"github.com/hiendv/gate/internal/test/fixtures"
	"github.com/hiendv/gate/oauth"
)

func TestOAuthInvalidConfig(t *testing.T) {
	instance := oauth.New(
		oauth.Config{},
		oauth.HandlerStub,
		// Services are omitted
		dependency.NewContainer(nil, nil, nil),
	)

	if instance != nil {
		t.Fatal("unexpected non-nil driver")
	}
}

func TestOAuthInvalidHandler(t *testing.T) {
	instance := oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"client-id",
			"client-secret",
			"http://localhost:8080",
		),
		nil,
		// Services are omitted
		dependency.NewContainer(nil, nil, nil),
	)

	if instance != nil {
		t.Fatal("unexpected non-nil driver")
	}
}

func TestOAuthLoginFunc(t *testing.T) {
	instance := oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"client-id",
			"client-secret",
			"http://localhost:8080",
		),
		func(user gate.Account) oauth.LoginFunc {
			return nil
		},
		// Services are omitted
		dependency.NewContainer(nil, nil, nil),
	)

	if instance != nil {
		t.Fatal("unexpected non-nil driver")
	}

	driver := oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"client-id",
			"client-secret",
			"http://localhost:8080",
		),
		fixtures.CodeAndStateOAuthHandler,
		// Token and Role services are omitted
		dependency.NewContainer(fixtures.NewMyUserService(
			[]fixtures.User{
				{
					ID:    fixtures.RandomString(8),
					Email: "email@gmail.com",
					Roles: []string{},
				},
			},
			[]string{"local", "gmail.com"},
		), nil, nil),
	)
	if driver == nil {
		t.Fatal("unexpected nil driver")
	}

	t.Run("valid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"code": "code", "state": "state"})
		test.AssertOK(t, err, "valid credentials")
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"code": ""})
		test.AssertErr(t, err, "invalid credentials")
	})
}

func TestOAuthUserService(t *testing.T) {
	t.Run("with invalid user service", func(t *testing.T) {
		driver := oauth.New(
			oauth.NewFacebookConfig(
				gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
				"client-id",
				"client-secret",
				"http://localhost:8080",
			),
			oauth.HandlerStub,
			// Role service is omitted
			dependency.NewContainer(nil, fixtures.NewMyTokenService(nil), nil),
		)
		if driver == nil {
			t.Fatal("unexpected nil driver")
		}

		t.Run("get user from jwt", func(t *testing.T) {
			user := fixtures.User{
				ID:    fixtures.RandomString(8),
				Email: "nobody@local",
				Roles: []string{},
			}

			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			token, err := driver.IssueJWT(user)
			test.AssertOK(t, err, "valid JWT service")

			_, err = driver.GetUserFromJWT(token)
			test.AssertErr(t, err, "missing user service")
		})

		t.Run("login", func(t *testing.T) {
			_, err := driver.Login(map[string]string{"code": "code", "state": "state"})
			test.AssertErr(t, err, "missing user service")
		})
	})
}

func TestPasswordJWTService(t *testing.T) {
	driver := oauth.New(
		oauth.NewFacebookConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"client-id",
			"client-secret",
			"http://localhost:8080",
		),
		oauth.HandlerStub,
		// User service is omitted
		dependency.NewContainer(nil, fixtures.NewMyTokenService(nil), fixtures.NewMyRoleService(nil)),
	)
	if driver == nil {
		t.Fatal("unexpected nil driver")
	}

	user := fixtures.User{
		ID:    fixtures.RandomString(8),
		Email: "nobody@local",
		Roles: []string{},
	}

	t.Run("issue", func(t *testing.T) {
		t.Run("with invalid JWT service", func(t *testing.T) {
			service, err := driver.JWTService()
			test.AssertOK(t, err, "valid JWT service")

			driver.SetJWTService(nil)
			_, err = driver.IssueJWT(user)
			test.AssertErr(t, err, "missing JWT service")

			driver.SetJWTService(service)
			_, err = driver.IssueJWT(user)
			test.AssertOK(t, err, "valid JWT service")
		})

		t.Run("with invalid JWT service configuration", func(t *testing.T) {
			service, err := driver.JWTService()
			test.AssertOK(t, err, "valid JWT service")

			// 0 is not a string
			serviceConfig, err := gate.NewHMACJWTConfig("HS256", 0, time.Hour*1, false)
			test.AssertOK(t, err, "valid JWT config")

			driver.SetJWTService(gate.NewJWTService(serviceConfig))
			_, err = driver.IssueJWT(user)
			test.AssertErr(t, err, "missing JWT service")

			driver.SetJWTService(service)
			_, err = driver.IssueJWT(user)
			test.AssertOK(t, err, "valid JWT service")
		})

		t.Run("with invalid token service", func(t *testing.T) {
			driverWithInvalidTokenService := oauth.New(
				oauth.NewFacebookConfig(
					gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
					"client-id",
					"client-secret",
					"http://localhost:8080",
				),
				oauth.HandlerStub,
				// User and Role services are omitted
				dependency.NewContainer(nil, nil, nil),
			)
			if driverWithInvalidTokenService == nil {
				t.Fatal("unexpected nil driver")
			}

			_, err := driverWithInvalidTokenService.TokenService()
			test.AssertErr(t, err, "invalid token service")

			_, err = driverWithInvalidTokenService.IssueJWT(user)
			test.AssertErr(t, err, "missing token service")
		})
	})

	t.Run("parse", func(t *testing.T) {
		t.Run("with invalid JWT service", func(t *testing.T) {
			service, err := driver.JWTService()
			test.AssertOK(t, err, "valid JWT service")

			token, err := driver.IssueJWT(user)
			test.AssertOK(t, err, "valid JWT service")

			driver.SetJWTService(nil)
			_, err = driver.ParseJWT(token.Value)
			test.AssertErr(t, err, "missing JWT service")

			driver.SetJWTService(service)
			_, err = driver.ParseJWT(token.Value)
			test.AssertOK(t, err, "valid JWT service")
		})
	})
}

func TestOAuthRoleService(t *testing.T) {
	user := fixtures.User{
		ID:    fixtures.RandomString(8),
		Email: "nobody@local",
		Roles: []string{"role-id"},
	}

	t.Run("get user abilities", func(t *testing.T) {
		t.Run("with invalid role service", func(t *testing.T) {
			driver := oauth.New(
				oauth.NewFacebookConfig(
					gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
					"client-id",
					"client-secret",
					"http://localhost:8080",
				),
				oauth.HandlerStub,
				// User and Token services are omitted
				dependency.NewContainer(nil, nil, nil),
			)
			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			_, err := driver.GetUserAbilities(user)
			test.AssertErr(t, err, "missing role service")
		})

		t.Run("with valid role service", func(t *testing.T) {
			driver := oauth.New(
				oauth.NewFacebookConfig(
					gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
					"client-id",
					"client-secret",
					"http://localhost:8080",
				),
				oauth.HandlerStub,
				// User and Token services are omitted
				dependency.NewContainer(nil, nil, fixtures.NewMyRoleService(nil)),
			)
			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			_, err := driver.GetUserAbilities(user)
			test.AssertErr(t, err, "missing role")
		})
	})
}

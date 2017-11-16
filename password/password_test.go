package password

import (
	"testing"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal/test"
	"github.com/hiendv/gate/internal/test/fixtures"
	"github.com/pkg/errors"
)

func TestPasswordInvalidConfig(t *testing.T) {
	instance := New(
		Config{},
		LoginFuncStub,
		// Services are omitted
		dependency.NewContainer(nil, nil, nil),
	)

	if instance != nil {
		t.Fatal("unexpected nil driver")
	}
}

func TestPasswordInvalidHandler(t *testing.T) {
	instance := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		nil,
		// Services are omitted
		dependency.NewContainer(nil, nil, nil),
	)

	if instance != nil {
		t.Fatal("unexpected nil driver")
	}
}

func TestPasswordLoginFunc(t *testing.T) {
	account := fixtures.Account{Email: "email@local", Password: "password"}

	driver := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(email, password string) (gate.HasEmail, error) {
			if account.Valid(email, password) {
				return account, nil
			}

			return nil, errors.New("invalid credentials")
		},
		// Token and Role services are omitted
		dependency.NewContainer(fixtures.NewMyUserService(nil), nil, nil),
	)
	if driver == nil {
		t.Fatal("unexpected non-nil driver")
	}

	t.Run("valid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"email": "email@local", "password": "password"})
		test.AssertOK(t, err, "valid credentials")
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"email": "email@local", "password": ""})
		test.AssertErr(t, err, "invalid credentials")
	})
}

func TestPasswordJWTService(t *testing.T) {
	driver := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		LoginFuncStub,
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
			driverWithInvalidTokenService := New(
				Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
				LoginFuncStub,
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

func TestPasswordUserService(t *testing.T) {
	t.Run("with invalid user service", func(t *testing.T) {
		driver := New(
			Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
			LoginFuncStub,
			// Role service is omitted
			dependency.NewContainer(nil, fixtures.NewMyTokenService(nil), nil),
		)
		if driver == nil {
			t.Fatal("unexpected non-nil driver")
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
			_, err := driver.Login(map[string]string{"email": "email@local", "password": "password"})
			test.AssertErr(t, err, "invalid credentials")
		})
	})
}

func TestPasswordRoleService(t *testing.T) {
	user := fixtures.User{
		ID:    fixtures.RandomString(8),
		Email: "nobody@local",
		Roles: []string{"role-id"},
	}

	t.Run("get user abilities", func(t *testing.T) {
		t.Run("with invalid role service", func(t *testing.T) {
			driver := New(
				Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
				LoginFuncStub,
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
			driver := New(
				Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
				LoginFuncStub,
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

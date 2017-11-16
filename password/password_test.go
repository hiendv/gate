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
		nil,
		dependency.NewContainer(&fixtures.MyUserService{}, &fixtures.MyTokenService{}, &fixtures.MyRoleService{}),
	)

	if instance != nil {
		t.Fatal("unexpected non-nil driver")
	}
}

func TestPasswordLoginFunc(t *testing.T) {
	driver := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(email, password string) (gate.User, error) {
			if email == "email@local" && password == "password" {
				return fixtures.User{}, nil
			}

			return nil, errors.New("invalid credentials")
		},
		dependency.NewContainer(&fixtures.MyUserService{}, &fixtures.MyTokenService{}, &fixtures.MyRoleService{}),
	)

	t.Run("valid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"email": "email@local", "password": "password"})
		if err != nil {
			t.Fatalf("err should be nil because of the valid credentials: %s", err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := driver.Login(map[string]string{"email": "email@local", "password": ""})
		if err == nil {
			t.Fatal("err should not be nil because of the invalid credentials")
		}
	})
}

func TestPasswordJWTService(t *testing.T) {
	driver := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		nil,
		dependency.NewContainer(&fixtures.MyUserService{}, &fixtures.MyTokenService{}, &fixtures.MyRoleService{}),
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
			driver := New(
				Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
				nil,
				dependency.NewContainer(&fixtures.MyUserService{}, nil, &fixtures.MyRoleService{}),
			)

			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			_, err := driver.TokenService()
			test.AssertErr(t, err, "invalid token service")

			_, err = driver.IssueJWT(user)
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
	user := fixtures.User{
		ID:    fixtures.RandomString(8),
		Email: "nobody@local",
		Roles: []string{},
	}

	t.Run("get user from jwt", func(t *testing.T) {
		t.Run("with invalid user service", func(t *testing.T) {
			driver := New(
				Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
				nil,
				dependency.NewContainer(nil, &fixtures.MyTokenService{}, &fixtures.MyRoleService{}),
			)

			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			token, err := driver.IssueJWT(user)
			test.AssertOK(t, err, "valid JWT service")

			_, err = driver.GetUserFromJWT(token)
			test.AssertErr(t, err, "missing user service")
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
				nil,
				dependency.NewContainer(&fixtures.MyUserService{}, &fixtures.MyTokenService{}, nil),
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
				nil,
				dependency.NewContainer(&fixtures.MyUserService{}, &fixtures.MyTokenService{}, &fixtures.MyRoleService{}),
			)

			if driver == nil {
				t.Fatal("unexpected nil driver")
			}

			_, err := driver.GetUserAbilities(user)
			test.AssertErr(t, err, "missing role")
		})
	})
}

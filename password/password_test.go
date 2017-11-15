package password

import (
	"testing"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
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

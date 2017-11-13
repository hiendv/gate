package password

import (
	"os"
	"testing"
	"time"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

var (
	auth   gate.Auth
	driver *Driver

	userService  myUserService
	tokenService myTokenService
	roleService  myRoleService
)

func TestMain(m *testing.M) {
	roles := []role{
		{
			id: randomString(8),
			abilities: []ability{
				{"GET", "/api/v1/*"},
				{"POST", "/api/v1/users*"},
			},
		},
		{
			id: randomString(8),
			abilities: []ability{
				{"GET", "*"},
			},
		},
		{
			id: randomString(8),
			abilities: []ability{
				{"POST", "/api/v1/posts*"},
			},
		},
	}

	userService = myUserService{
		[]user{
			{
				id:    randomString(8),
				email: "foo@local",
				roles: []string{
					roles[0].id,
					roles[1].id,
				},
			},
		},
	}

	tokenService = myTokenService{}
	roleService = myRoleService{roles}

	// prepare for mocking
	driver = New(
		gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
		gate.NewDependencies(&userService, &tokenService, &roleService),
		func(email, password string) (gate.User, error) {
			for _, record := range credentials {
				if record.Valid(email, password) {
					return userService.FindOrCreateOneByEmail(record.GetEmail())
				}
			}

			return nil, errors.New("invalid credentials")
		},
	)
	auth = driver

	os.Exit(m.Run())
}

func TestLogin(t *testing.T) {
	t.Run("login func", func(t *testing.T) {
		handler := driver.handler

		driver.handler = func(email, password string) (gate.User, error) {
			if email == "email@local" && password == "password" {
				return user{}, nil
			}

			return nil, errors.New("invalid credentials")
		}

		t.Run("valid", func(t *testing.T) {
			_, err := auth.Login(map[string]string{"email": "email@local", "password": "password"})
			if err != nil {
				t.Fatalf("err should be nil because of the valid credentials: %s", err)
			}
		})

		t.Run("invalid", func(t *testing.T) {
			_, err := auth.Login(map[string]string{"email": "email@local", "password": ""})
			if err == nil {
				t.Fatalf("err should not be nil because of the invalid credentials")
			}
		})

		driver.handler = handler
	})

	t.Run("valid login", func(t *testing.T) {
		t.Run("first time", func(t *testing.T) {
			_, err := userService.findOneByEmail("bar@local")
			if err == nil {
				t.Fatalf("err should be userNotFound because of the non-existing user")
			}

			firstUser, err := auth.Login(map[string]string{"email": "bar@local", "password": "barr"})
			if err != nil {
				t.Fatalf("err should be nil because of the valid credentials: %s", err)
			}

			secondUser, err := auth.Login(map[string]string{"email": "bar@local", "password": "barr"})
			if err != nil {
				t.Fatalf("err should be nil because of the valid credentials: %s", err)
			}

			if firstUser.GetID() != secondUser.GetID() {
				t.Errorf("ids should be equal: %v - %v", firstUser.GetID(), secondUser.GetID())
			}

			_, err = userService.findOneByEmail("bar@local")
			if err != nil {
				t.Fatalf("err should be nil because of the existing user: %s", err)
			}
		})

		t.Run("later", func(t *testing.T) {
			firstUser, err := userService.findOneByEmail("foo@local")
			if err != nil {
				t.Fatalf("err should not be nil because of the existing user: %s", err)
			}

			secondUser, err := auth.Login(map[string]string{"email": "foo@local", "password": "fooo"})
			if err != nil {
				t.Fatalf("err should be nil because of the valid credentials: %s", err)
			}

			if firstUser.GetID() != secondUser.GetID() {
				t.Errorf("ids should be equal: %v - %v", firstUser.GetID(), secondUser.GetID())
			}
		})
	})

	t.Run("invalid login", func(t *testing.T) {
		_, err := auth.Login(map[string]string{"email": "foo", "password": "barr"})
		if err == nil {
			t.Fatalf("err should not be nil because of the invalid credentials")
		}
	})
}

func testJWTIssue(t *testing.T) {
	user, err := userService.findOneByEmail("foo@local")
	if err != nil {
		t.Fatalf("err should not be nil because of the existing user: %s", err)
	}

	token, err := auth.IssueJWT(user)
	if err != nil {
		t.Fatalf("err should not be nil: %s", err)
	}

	if user.GetID() != token.UserID {
		t.Fatalf("id mismatch: %s - %s", user.GetID(), token.UserID)
	}

	_, err = tokenService.FindOneByID(token.ID)
	if err != nil {
		t.Fatalf("err should be nil because of the existing token: %s", err)
	}
}

func testJWTValidateParseAndFetchUser(t *testing.T) {
	user, err := userService.findOneByEmail("foo@local")
	if err != nil {
		t.Fatalf("err should not be nil because of the existing user: %s", err)
	}

	token, err := auth.IssueJWT(user)
	if err != nil {
		t.Fatalf("err should not be nil: %s", err)
	}

	tokenString, err := auth.ParseJWT(token.Value)
	if err != nil {
		t.Fatalf("err should be nil because of the valid token: %s", err)
	}

	_, err = auth.GetUserFromJWT(tokenString)
	if err != nil {
		t.Fatalf("err should be nil because of the existing user: %s", err)
	}
}

func testJWTValidateAuthenticate(t *testing.T) {
	user, err := userService.findOneByEmail("foo@local")
	if err != nil {
		t.Fatalf("err should not be nil because of the existing user: %s", err)
	}

	token, err := auth.IssueJWT(user)
	if err != nil {
		t.Fatalf("err should not be nil: %s", err)
	}

	_, err = auth.Authenticate(token.Value)
	if err != nil {
		t.Fatalf("err should be nil because of the existing user: %s", err)
	}
}

func testJWTValidateAuthorize(t *testing.T) {
	user, err := userService.findOneByEmail("foo@local")
	if err != nil {
		t.Fatalf("err should not be nil because of the existing user: %s", err)
	}

	token, err := auth.IssueJWT(user)
	if err != nil {
		t.Fatalf("err should not be nil: %s", err)
	}

	user, err = auth.Authenticate(token.Value)
	if err != nil {
		t.Fatalf("err should be nil because of the existing user: %s", err)
	}

	err = auth.Authorize(user, "GET", "/api")
	if err != nil {
		t.Fatalf("err should be nil because of the valid abilities: %s", err)
	}

	err = auth.Authorize(user, "GET", "/api/v1/users")
	if err != nil {
		t.Fatalf("err should be nil because of the valid abilities: %s", err)
	}

	err = auth.Authorize(user, "GET", "/api/v1/posts")
	if err != nil {
		t.Fatalf("err should be nil because of the valid abilities: %s", err)
	}

	err = auth.Authorize(user, "POST", "/api/v1/posts")
	if err == nil {
		t.Fatal("err should not be nil because of the invalid abilities")
	}
}

func TestJWT(t *testing.T) {
	t.Run("issue", testJWTIssue)
	t.Run("validate", func(t *testing.T) {
		t.Run("parse and fetch user", testJWTValidateParseAndFetchUser)
		t.Run("authenticate", testJWTValidateAuthenticate)
		t.Run("authorize", testJWTValidateAuthorize)
	})
}

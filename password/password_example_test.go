package password

import (
	"fmt"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/test/fixtures"
	"github.com/pkg/errors"
)

func Example() {
	var auth gate.Auth

	userService := fixtures.NewMyUserService([]fixtures.User{
		{
			ID:    "id",
			Email: "email@local",
			Roles: []string{"role-id"},
		},
	})
	tokenService := &fixtures.MyTokenService{}
	roleService := fixtures.NewMyRoleService([]fixtures.Role{
		{
			ID: "role-id",
			Abilities: []fixtures.Ability{
				{"GET", "/api/v1/*"},
				{"POST", "/api/v1/users*"},
			},
		},
	})

	auth = New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(email, password string) (gate.User, error) {
			if email == "email@local" && password == "password" {
				return userService.FindOrCreateOneByEmail(email)
			}

			return nil, errors.New("invalid credentials")
		},
		dependency.NewContainer(userService, tokenService, roleService),
	)

	user, err := auth.Login(map[string]string{"email": "email@local", "password": "password"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Tokens: %d\n", tokenService.Count())

	jwt, err := auth.IssueJWT(user)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Tokens: %d\n", tokenService.Count())

	parsedUser, err := auth.Authenticate(jwt.Value)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", parsedUser.GetID(), parsedUser.GetEmail(), err)

	err = auth.Authorize(parsedUser, "GET", "/api/v1/users")
	fmt.Printf("%v\n", err)

	err = auth.Authorize(parsedUser, "GET", "/api/v1/posts")
	fmt.Printf("%v\n", err)

	err = auth.Authorize(parsedUser, "POST", "/api/v1/users")
	fmt.Printf("%v\n", err)

	err = auth.Authorize(parsedUser, "POST", "/api/v1/posts")
	fmt.Printf("%v\n", err)

	// Output:
	// Tokens: 0
	// Tokens: 1
	// id:email@local - <nil>
	// <nil>
	// <nil>
	// <nil>
	// forbidden
}

func ExampleDriver_Login() {

	userService := fixtures.NewMyUserService([]fixtures.User{
		{
			ID:    "id",
			Email: "email@local",
			Roles: []string{"role-id"},
		},
	})

	auth := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(email, password string) (gate.User, error) {
			if email == "email@local" && password == "password" {
				return userService.FindOrCreateOneByEmail(email)
			}

			if email == "email2@local" && password == "password2" {
				return userService.FindOrCreateOneByEmail(email)
			}

			return nil, errors.New("invalid credentials")
		},
		dependency.NewContainer(userService, nil, nil),
	)

	if auth == nil {
		return
	}

	user, err := auth.Login(map[string]string{"email": "email@local", "password": "password"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", user.GetID(), user.GetEmail(), err)

	userService.GenerateMyUserID = func() string {
		return "a-fixed-id"
	}

	secondUser, err := auth.Login(map[string]string{"email": "email2@local", "password": "password2"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", secondUser.GetID(), secondUser.GetEmail(), err)

	// Output:
	// id:email@local - <nil>
	// a-fixed-id:email2@local - <nil>
}

func ExampleDriver_IssueJWT() {
	auth := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(email, password string) (gate.User, error) {
			if email == "email@local" && password == "password" {
				return fixtures.User{"id", "email@local", []string{"role"}}, nil
			}

			return nil, errors.New("invalid credentials")
		},
		dependency.NewContainer(nil, &fixtures.MyTokenService{}, nil),
	)

	jwtConfig, err := gate.NewHMACJWTConfig("HS256", auth.config.JWTSigningKey(), auth.config.JWTExpiration(), auth.config.JWTSkipClaimsValidation())
	if err != nil {
		fmt.Println(err)
		return
	}

	mockedJWTService := gate.NewJWTService(jwtConfig)
	mockedJWTService.Now = func() time.Time {
		return time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC)
	}
	mockedJWTService.GenerateClaimsID = func() string {
		return "claims-id"
	}

	auth.Container.SetJWTService(mockedJWTService)

	user, err := auth.Login(map[string]string{"email": "email@local", "password": "password"})
	if err != nil {
		fmt.Println(err)
		return
	}

	jwt, err := auth.IssueJWT(user)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s@%s - %v", jwt.ID, jwt.Value, jwt.UserID, err)

	// Output: claims-id:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiaWQiLCJlbWFpbCI6ImVtYWlsQGxvY2FsIiwicm9sZXMiOlsicm9sZSJdfSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDB9.aCp3Bx6aH48sYAeCSXhQyXGAYTiyr9VSkC3mT7dmUeE@id - <nil>
}

func ExampleDriver_Authenticate() {
	auth := New(
		Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, true)},
		nil,
		dependency.NewContainer(
			fixtures.NewMyUserService([]fixtures.User{
				{
					ID:    "id",
					Email: "email@local",
					Roles: []string{},
				},
			}),
			&fixtures.MyTokenService{},
			nil,
		),
	)

	user, err := auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiaWQiLCJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsicm9sZSJdfSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDB9.b0gxC2uZRek-SPwHSqyLOoW_DjSYroSivLqJG96Zxl0")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v", user.GetID(), user.GetEmail(), err)

	// Output: id:email@local - <nil>
}

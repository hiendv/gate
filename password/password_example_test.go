package password

import (
	"errors"
	"fmt"
	"time"

	"github.com/hiendv/gate"
)

func Example() {
	var auth gate.Auth

	tokenService := &myTokenService{}
	userService := &myUserService{
		[]user{
			{
				id:       "id",
				username: "username",
				roles:    []string{"role-id"},
			},
		},
	}
	roleService := &myRoleService{
		[]role{
			{
				id: "role-id",
				abilities: []ability{
					{"GET", "/api/v1/*"},
					{"POST", "/api/v1/users*"},
				},
			},
		},
	}

	auth = New(
		gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
		gate.NewDependencies(userService, tokenService, roleService),
		func(username, password string) (gate.User, error) {
			if username == "username" && password == "password" {
				return userService.FindOrCreateOneByUsername(username)
			}

			return nil, errors.New("invalid credentials")
		},
	)

	user, err := auth.Login(map[string]string{"username": "username", "password": "password"})
	if err != nil {
		return
	}

	fmt.Printf("Tokens: %d\n", len(tokenService.records))

	jwt, err := auth.IssueJWT(user)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Tokens: %d\n", len(tokenService.records))

	parsedUser, err := auth.Authenticate(jwt.Value)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", parsedUser.GetID(), parsedUser.GetUsername(), err)

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
	// id:username - <nil>
	// <nil>
	// <nil>
	// <nil>
	// forbidden
}

func ExampleDriver_Login() {
	userService := &myUserService{
		[]user{
			{
				id:       "id",
				username: "username",
				roles:    []string{"role-id"},
			},
		},
	}

	auth := New(
		gate.Config{},
		gate.NewDependencies(userService, nil, nil),
		func(username, password string) (gate.User, error) {
			if username == "username" && password == "password" {
				return userService.FindOrCreateOneByUsername(username)
			}

			if username == "username2" && password == "password2" {
				return userService.FindOrCreateOneByUsername(username)
			}

			return nil, errors.New("invalid credentials")
		},
	)

	user, err := auth.Login(map[string]string{"username": "username", "password": "password"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", user.GetID(), user.GetUsername(), err)

	generateMyUserID = func() string {
		return "a-fixed-id"
	}

	secondUser, err := auth.Login(map[string]string{"username": "username2", "password": "password2"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", secondUser.GetID(), secondUser.GetUsername(), err)

	// Output:
	// id:username - <nil>
	// a-fixed-id:username2 - <nil>
}

func ExampleDriver_IssueJWT() {
	auth := New(
		gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
		gate.NewDependencies(nil, &myTokenService{}, nil),
		func(username, password string) (gate.User, error) {
			if username == "username" && password == "password" {
				return user{"id", "username", []string{"role"}}, nil
			}

			return nil, errors.New("invalid credentials")
		},
	)

	jwtConfig, err := gate.NewHMACJWTConfig("HS256", auth.config.JWTSigningKey(), auth.config.JWTExpiration(), auth.config.JWTSkipClaimsValidation())
	if err != nil {
		return
	}

	mockedJWTService := gate.NewJWTService(jwtConfig)
	mockedJWTService.Now = func() time.Time {
		return time.Date(2020, time.November, 10, 23, 0, 0, 0, time.UTC)
	}
	mockedJWTService.GenerateClaimsID = func() string {
		return "claims-id"
	}

	auth.dependencies.SetJWTService(mockedJWTService)

	user, err := auth.Login(map[string]string{"username": "username", "password": "password"})
	if err != nil {
		return
	}

	jwt, err := auth.IssueJWT(user)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s@%s - %v", jwt.ID, jwt.Value, jwt.UserID, err)

	// Output: claims-id:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiaWQiLCJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsicm9sZSJdfSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDB9.b0gxC2uZRek-SPwHSqyLOoW_DjSYroSivLqJG96Zxl0@id - <nil>
}

func ExampleDriver_Authenticate() {
	auth := New(
		gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, true),
		gate.NewDependencies(
			&myUserService{
				[]user{
					{
						id:       "id",
						username: "username",
						roles:    []string{},
					},
				},
			},
			&myTokenService{},
			nil,
		),
		nil,
	)

	user, err := auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiaWQiLCJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsicm9sZSJdfSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDB9.b0gxC2uZRek-SPwHSqyLOoW_DjSYroSivLqJG96Zxl0")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v", user.GetID(), user.GetUsername(), err)

	// Output: id:username - <nil>
}

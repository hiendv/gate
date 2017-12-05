package password_test

import (
	"fmt"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal/test/fixtures"
	"github.com/hiendv/gate/password"
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
	tokenService := fixtures.NewMyTokenService(nil)
	roleService := fixtures.NewMyRoleService([]fixtures.Role{
		{
			ID: "role-id",
			Abilities: []fixtures.Ability{
				{Action: "GET", Object: "/api/v1/*"},
				{Action: "POST", Object: "/api/v1/users*"},
			},
		},
	})

	account := fixtures.Account{Email: "email@local", Password: "password"}

	auth = password.New(
		password.Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(driver password.Driver, email, password string) (gate.HasEmail, error) {
			if account.Valid(email, password) {
				return account, nil
			}

			return nil, errors.New("invalid credentials")
		},
		dependency.NewContainer(userService, tokenService, roleService),
	)
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

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

	account := fixtures.Account{Email: "email@local", Password: "password"}
	anotherAccount := fixtures.Account{Email: "email2@local", Password: "password2"}

	auth := password.New(
		password.Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)},
		func(driver password.Driver, email, password string) (gate.HasEmail, error) {
			if account.Valid(email, password) {
				return account, nil
			}

			if anotherAccount.Valid(email, password) {
				return anotherAccount, nil
			}

			return nil, errors.New("invalid credentials")
		},
		// Token and Role services are omitted
		dependency.NewContainer(userService, nil, nil),
	)
	if auth == nil {
		fmt.Println("auth should not be nil")
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
	userService := fixtures.NewMyUserService([]fixtures.User{
		{
			ID:    "id",
			Email: "email@local",
			Roles: []string{"role"},
		},
	})
	tokenService := fixtures.NewMyTokenService(nil)
	account := fixtures.Account{Email: "email@local", Password: "password"}
	config := password.Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false)}

	auth := password.New(
		config,
		func(driver password.Driver, email, password string) (gate.HasEmail, error) {
			if account.Valid(email, password) {
				return account, nil
			}

			return nil, errors.New("invalid credentials")
		},
		// Role service is omitted
		dependency.NewContainer(userService, tokenService, nil),
	)
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

	jwtConfig, err := gate.NewHMACJWTConfig("HS256", config.JWTSigningKey(), config.JWTExpiration(), config.JWTSkipClaimsValidation())
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

	// Output: claims-id:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImVtYWlsQGxvY2FsIiwicm9sZXMiOlsicm9sZSJdLCJleHAiOjE2MDUwNTI4MDAsImp0aSI6ImNsYWltcy1pZCIsImlhdCI6MTYwNTA0OTIwMCwic3ViIjoiaWQifQ.wRouDwptboRBSK-bXHugYeorWGy7pfUHstH_jEHKl_4@id - <nil>
}

func ExampleDriver_Authenticate() {
	userService := fixtures.NewMyUserService([]fixtures.User{
		{
			ID:    "id",
			Email: "email@local",
			Roles: []string{},
		},
	})
	tokenService := fixtures.NewMyTokenService(nil)

	auth := password.New(
		password.Config{gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, true)},
		password.LoginFuncStub,
		// Role service is omitted
		dependency.NewContainer(userService, tokenService, nil),
	)
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

	user, err := auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImVtYWlsQGxvY2FsIiwicm9sZXMiOlsicm9sZSJdLCJleHAiOjE2MDUwNTI4MDAsImp0aSI6ImNsYWltcy1pZCIsImlhdCI6MTYwNTA0OTIwMCwic3ViIjoiaWQifQ.wRouDwptboRBSK-bXHugYeorWGy7pfUHstH_jEHKl_4")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v", user.GetID(), user.GetEmail(), err)

	// Output: id:email@local - <nil>
}

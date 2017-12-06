package oauth_test

import (
	"fmt"
	"time"

	"github.com/hiendv/gate"
	"github.com/hiendv/gate/dependency"
	"github.com/hiendv/gate/internal/test/fixtures"
	"github.com/hiendv/gate/oauth"
)

func Example() {
	var auth gate.Auth

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
			ID:    "id",
			Email: "foo@local",
			Roles: []string{
				roles[0].ID,
				roles[1].ID,
			},
		},
		{
			ID:    "id2",
			Email: "bar@local",
			Roles: []string{},
		},
		{
			ID:    "id3",
			Email: "nobody@local",
			Roles: []string{},
		},
	}

	roleService := fixtures.NewMyRoleService(roles)
	userService := fixtures.NewMyUserService(users, []string{"local"})
	tokenService := fixtures.NewMyTokenService(nil)

	driver = oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"google-client-id",
			"google-client-secret",
			"http://localhost:8080",
		),
		oauth.StatelessHandler,
		dependency.NewContainer(userService, tokenService, roleService),
	)

	// Mocking
	driver.SetProvider(fixtures.OAuthProvider{
		map[string]gate.Account{
			"code-token": oauth.GoogleUser{
				Email:         "foo@local",
				EmailVerified: true,
			},
		},
	})

	auth = driver
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

	user, err := auth.Login(map[string]string{"code": "code"})
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
	// id:foo@local - <nil>
	// <nil>
	// <nil>
	// <nil>
	// forbidden
}

func ExampleDriver_Login() {
	var auth gate.Auth

	users := []fixtures.User{
		{
			ID:    "id",
			Email: "foo@local",
			Roles: []string{},
		},
		{
			ID:    "id2",
			Email: "bar@local",
			Roles: []string{},
		},
	}

	userService := fixtures.NewMyUserService(users, []string{"local"})

	driver = oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
			"google-client-id",
			"google-client-secret",
			"http://localhost:8080",
		),
		oauth.StatelessHandler,
		// Token and Role services are omitted
		dependency.NewContainer(userService, nil, nil),
	)

	// Mocking
	driver.SetProvider(fixtures.OAuthProvider{
		map[string]gate.Account{
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
				EmailVerified: true,
			},
		},
	})

	auth = driver
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

	user, err := auth.Login(map[string]string{"code": "code"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", user.GetID(), user.GetEmail(), err)

	secondUser, err := auth.Login(map[string]string{"code": "code2"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", secondUser.GetID(), secondUser.GetEmail(), err)

	thirdUser, err := auth.Login(map[string]string{"code": "code3"})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v\n", thirdUser.GetID(), thirdUser.GetEmail(), err)

	// Output:
	// id:foo@local - <nil>
	// id:foo@local - <nil>
	// id2:bar@local - <nil>
}

func ExampleDriver_IssueJWT() {
	var auth gate.Auth

	users := []fixtures.User{
		{
			ID:    "id",
			Name:  "foo",
			Email: "foo@local",
			Roles: []string{},
		},
	}

	userService := fixtures.NewMyUserService(users, []string{"local"})
	tokenService := fixtures.NewMyTokenService(nil)
	config := oauth.NewGoogleConfig(
		gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, false),
		"google-client-id",
		"google-client-secret",
		"http://localhost:8080",
	)

	driver = oauth.New(
		config,
		oauth.StatelessHandler,
		// Role service is omitted
		dependency.NewContainer(userService, tokenService, nil),
	)

	// Mocking
	driver.SetProvider(fixtures.OAuthProvider{
		map[string]gate.Account{
			"code-token": oauth.GoogleUser{
				Email:         "foo@local",
				EmailVerified: true,
			},
		},
	})

	auth = driver
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

	driver.Container.SetJWTService(mockedJWTService)

	user, err := auth.Login(map[string]string{"code": "code"})
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

	// Output: claims-id:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiZm9vIiwiZW1haWwiOiJmb29AbG9jYWwiLCJyb2xlcyI6W10sImV4cCI6MTYwNTA1MjgwMCwianRpIjoiY2xhaW1zLWlkIiwiaWF0IjoxNjA1MDQ5MjAwLCJzdWIiOiJpZCJ9.vrl-kgbwywz7x25ebq55F9smv20vkO23z-8XaZkWYX0@id - <nil>
}

func ExampleDriver_Authenticate() {
	users := []fixtures.User{
		{
			ID:    "id",
			Email: "foo@local",
			Roles: []string{},
		},
	}

	userService := fixtures.NewMyUserService(users, []string{"local"})
	tokenService := fixtures.NewMyTokenService(nil)

	auth := oauth.New(
		oauth.NewGoogleConfig(
			gate.NewConfig("jwt-secret", "jwt-secret", time.Hour*1, true),
			"google-client-id",
			"google-client-secret",
			"http://localhost:8080",
		),
		oauth.StatelessHandler,
		// Role service is omitted
		dependency.NewContainer(userService, tokenService, nil),
	)
	if auth == nil {
		fmt.Println("auth should not be nil")
		return
	}

	user, err := auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImZvb0Bsb2NhbCIsInJvbGVzIjpbXSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDAsInN1YiI6ImlkIn0.W11In6qyrtGdZ_XD3eOJBpd5qwruJE-F3ACstvUcagI")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s:%s - %v", user.GetID(), user.GetEmail(), err)

	// Output: id:foo@local - <nil>
}

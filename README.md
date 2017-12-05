# Gate
[![Build Status](https://travis-ci.org/hiendv/gate.svg?branch=master)](https://travis-ci.org/hiendv/gate) [![GoDoc](https://godoc.org/github.com/hiendv/gate?status.svg)](https://godoc.org/github.com/hiendv/gate) [![Go Report Card](https://goreportcard.com/badge/github.com/hiendv/gate)](https://goreportcard.com/report/github.com/hiendv/gate) [![Coverage Status](https://coveralls.io/repos/github/hiendv/gate/badge.svg?branch=master)](https://coveralls.io/github/hiendv/gate?branch=master)

<p align="center">
	<img src="bouncer.svg" alt="Golang Gate" title="Golang Gate" />
	<br/>
	An authentication and RBAC authorization library using JWT for Go 1.7+
</p>

### Features
- Simple and well-tested API
- Exported flexible contracts
- Developer friendly
- Persistence free

### Supported authentication drivers
- Password-based authentication
- OAuth2

### Installation
```bash
go get github.com/hiendv/gate
```

### Usage
Quick example to get a taste of Gate
```go
var auth gate.Auth
var user gate.User
var err error

// some construction codes go here

// Login using password-based authentication
user, err = auth.Login(map[string]string{"email": "email", "password": "password"})
if err != nil {
	log.Fatal("oops")
}

// Login using OAuth
// Redirect users to the authentication code URL
url, err := auth.LoginURL("state")

// Receive the code and exchange it
user, err = auth.Login(map[string]string{"code": "received-code"})
if err != nil {
	log.Fatal("oops")
}

// Issue the JWT for the user
jwt, err := auth.IssueJWT(user)
if err != nil {
	log.Fatal("oops")
}

// Send the JWT to the user and let them use it to authenticate

// Authenticate a user using a given JWT
user, err = auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImVtYWlsQGxvY2FsIiwicm9sZXMiOlsicm9sZSJdLCJleHAiOjE2MDUwNTI4MDAsImp0aSI6ImNsYWltcy1pZCIsImlhdCI6MTYwNTA0OTIwMCwic3ViIjoiaWQifQ.wRouDwptboRBSK-bXHugYeorWGy7pfUHstH_jEHKl_4")
if err != nil {
	log.Fatal("oops")
}

err = auth.Authorize(user, "action", "object")
```

You may want to check these examples and tests:
- Password-based authentication [examples](https://godoc.org/github.com/hiendv/gate/password#pkg-examples), [unit tests](password/password_test.go) & [integration tests](password/password_integration_test.go)
- OAuth2 authentication [examples](https://godoc.org/github.com/hiendv/gate/oauth#pkg-examples), [unit tests](oauth/oauth_test.go) & [integration tests](oauth/oauth_integration_test.go)

## Development & Testing
Please check the [Contributing Guidelines](https://github.com/hiendv/gate/blob/master/CONTRIBUTING.md).

## Contribution
Issues and PRs are welcome !

### Credits
*The [Gate bouncer logo](https://github.com/hiendv/gate/blob/master/bouncer.svg) is licensed under the Creative Commons 4.0 Attributions license.*  
*The [original gopher.svg](https://github.com/golang-samples/gopher-vector/blob/master/gopher.svg) was created by [Takuya Ueda](https://twitter.com/tenntenn), licensed under the Creative Commons 3.0 Attributions license.*  
*The [Go Gopher](https://blog.golang.org/gopher) was designed by [Renee French](http://reneefrench.blogspot.com), licensed under the Creative Commons 3.0 Attributions license.*

Big thanks to:
- [dgrijalva/jwt-go](https://github.com/dgrijalva/jwt-go) for the enormous help dealing with JWT works
- [rs/xid](https://github.com/rs/xid) for the claims ID generator

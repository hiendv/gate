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
- OAuth2 (coming soon)

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

// some codes go here

// Login using password-based authentication & Issue the JWT
user, err = auth.Login(map[string]string{"email": "email", "password": "password"})
jwt, err := auth.IssueJWT(user)

// Authenticate with a given JWT
user, err = auth.Authenticate("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoiaWQiLCJ1c2VybmFtZSI6InVzZXJuYW1lIiwicm9sZXMiOlsicm9sZSJdfSwiZXhwIjoxNjA1MDUyODAwLCJqdGkiOiJjbGFpbXMtaWQiLCJpYXQiOjE2MDUwNDkyMDB9.b0gxC2uZRek-SPwHSqyLOoW_DjSYroSivLqJG96Zxl0")
err = auth.Authorize(user, "action", "object")
```

You may want to check these examples and tests:
- Password-based authentication [examples](https://godoc.org/github.com/hiendv/gate/password#pkg-examples) & [tests](password/password_test.go)

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
- [satori/go.uuid](https://github.com/satori/go.uuid) for the claims ID generator

package gate

import (
	"time"
)

// Config is the configuration for Auth
type Config struct {
	jwtSigningKey           interface{}
	jwtVerifyingKey         interface{}
	jwtExpiration           time.Duration
	jwtSkipClaimsValidation bool
}

// JWTSigningKey is the setter for JWT signing key configuration
func (config Config) JWTSigningKey() interface{} {
	return config.jwtSigningKey
}

// JWTVerifyingKey is the setter for JWT verifying key configuration
func (config Config) JWTVerifyingKey() interface{} {
	return config.jwtVerifyingKey
}

// JWTExpiration is the setter for JWT expiration configuration
func (config Config) JWTExpiration() time.Duration {
	return config.jwtExpiration
}

// JWTSkipClaimsValidation is the setter for JWT claims validation skip configuration
func (config Config) JWTSkipClaimsValidation() bool {
	return config.jwtSkipClaimsValidation
}

// NewConfig is the constructor for Config
func NewConfig(jwtSigningKey, jwtVerifyingKey interface{}, jwtExpiration time.Duration, jwtSkipClaimsValidation bool) Config {
	return Config{jwtSigningKey, jwtVerifyingKey, jwtExpiration, jwtSkipClaimsValidation}
}

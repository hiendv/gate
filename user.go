package gate

// User is the contract for the user entity
type User interface {
	GetID() string
	GetUsername() string
	GetRoles() []string
}

// Role is the contract for the role entity
type Role interface {
	GetAbilities() []UserAbility
}

// UserAbility is the contract for the ability entity
type UserAbility interface {
	GetAction() string
	GetObject() string
}

// UserInfo is the user information entity
type UserInfo struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

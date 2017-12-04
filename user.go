package gate

// User is the contract for the user entity
type User interface {
	GetID() string
	GetEmail() string
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

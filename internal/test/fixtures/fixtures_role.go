package fixtures

import (
	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

// Ability is my user ability
type Ability struct {
	Action string
	Object string
}

// GetAction returns ability action
func (a Ability) GetAction() string {
	return a.Action
}

// GetObject returns ability object
func (a Ability) GetObject() string {
	return a.Object
}

// Role is my user role
type Role struct {
	ID        string
	Abilities []Ability
}

// GetAbilities returns role abilities
func (r Role) GetAbilities() (abilities []gate.UserAbility) {
	abilities = make([]gate.UserAbility, len(r.Abilities))

	for i, ability := range r.Abilities {
		abilities[i] = ability
	}

	return
}

// MyRoleService is my role service
type MyRoleService struct {
	records []Role
}

// NewMyRoleService is the constructor for MyRoleService
func NewMyRoleService(records []Role) *MyRoleService {
	return &MyRoleService{records}
}

// FindByIDs fetches roles with the given IDs
func (service MyRoleService) FindByIDs(ids []string) (roles []gate.Role, err error) {
	for _, record := range service.records {
		for _, id := range ids {
			if record.ID == id {
				roles = append(roles, record)
				continue
			}
		}
	}

	if len(roles) == 0 {
		err = errors.New("not found")
	}

	return
}

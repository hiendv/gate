package password

import (
	"github.com/hiendv/gate"
)

type ability struct {
	action string
	object string
}

func (a ability) GetAction() string {
	return a.action
}

func (a ability) GetObject() string {
	return a.object
}

type role struct {
	id        string
	abilities []ability
}

func (r role) GetAbilities() (abilities []gate.UserAbility) {
	abilities = make([]gate.UserAbility, len(r.abilities))

	for i, ability := range r.abilities {
		abilities[i] = ability
	}

	return
}

type myRoleService struct {
	records []role
}

func (service myRoleService) FindByIDs(ids []string) (roles []gate.Role, err error) {
	for _, record := range service.records {
		for _, id := range ids {
			if record.id == id {
				roles = append(roles, record)
				continue
			}
		}
	}
	return
}

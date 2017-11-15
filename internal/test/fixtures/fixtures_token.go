package fixtures

import (
	"time"

	"github.com/hiendv/gate"
	"github.com/pkg/errors"
)

var errTokenNotFound = errors.New("token not found")

type token struct {
	id        string
	value     string
	userID    string
	expiredAt time.Time
	issuedAt  time.Time
}

// MyTokenService is my token service
type MyTokenService struct {
	records []token
}

// Store appends the token
func (service *MyTokenService) Store(jwt gate.JWT) error {
	service.records = append(service.records, token{
		jwt.ID,
		jwt.Value,
		jwt.UserID,
		jwt.ExpiredAt,
		jwt.IssuedAt,
	})
	return nil
}

// FindOneByID fetches the JWT with the given ID
func (service MyTokenService) FindOneByID(id string) (jwt gate.JWT, err error) {
	for _, record := range service.records {
		if record.id == id {
			jwt = gate.JWT{
				ID:        record.id,
				Value:     record.value,
				UserID:    record.userID,
				ExpiredAt: record.expiredAt,
				IssuedAt:  record.issuedAt,
			}
			err = nil
			return
		}
	}
	err = errTokenNotFound
	return
}

// Count returns the number of records
func (service MyTokenService) Count() int {
	return len(service.records)
}

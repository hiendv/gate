package password

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

type myTokenService struct {
	records []token
}

func (service *myTokenService) Store(jwt gate.JWT) error {
	service.records = append(service.records, token{
		jwt.ID,
		jwt.Value,
		jwt.UserID,
		jwt.ExpiredAt,
		jwt.IssuedAt,
	})
	return nil
}

func (service myTokenService) FindOneByID(id string) (jwt gate.JWT, err error) {
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

package fixtures

type Account struct {
	Email    string
	Password string
}

func (record Account) GetEmail() string {
	return record.Email
}

func (record Account) Valid(email, password string) bool {
	return record.Email == email && record.Password == password
}

// var Accounts = []Account{
// 	{"foo@local", "fooo"},
// 	{"bar@local", "barr"},
// }

package password

type credential struct {
	email    string
	password string
}

func (record credential) GetEmail() string {
	return record.email
}

func (record credential) Valid(email, password string) bool {
	return record.GetEmail() == email && record.password == password
}

var credentials = []credential{
	{password: "fooo", email: "foo@local"},
	{password: "barr", email: "bar@local"},
}

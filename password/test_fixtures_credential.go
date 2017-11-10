package password

type credential struct {
	id       string
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
	{id: randomString(8), password: "fooo", email: "foo@local"},
	{id: randomString(8), password: "barr", email: "bar@local"},
}

package fixtures

// Account contains login credentials
type Account struct {
	Name       string
	Email      string
	Password   string
	EmptyEmail bool
}

// GetName returns the account's name
func (record Account) GetName() string {
	return record.Name
}

// GetEmail returns the account's email
func (record Account) GetEmail() string {
	if record.EmptyEmail {
		return ""
	}

	return record.Email
}

// Valid checks if the given credentials match the account
func (record Account) Valid(email, password string) bool {
	return record.Email == email && record.Password == password
}

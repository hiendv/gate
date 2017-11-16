package fixtures

// Account contains login credentials
type Account struct {
	Email    string
	Password string
}

// GetEmail returns the account's email
func (record Account) GetEmail() string {
	return record.Email
}

// Valid checks if the given credentials match the account
func (record Account) Valid(email, password string) bool {
	return record.Email == email && record.Password == password
}

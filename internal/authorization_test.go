package internal

import (
	"testing"
)

type myAbility struct {
	action string
	object string
}

// GetAction returns ability action
func (a myAbility) GetAction() string {
	return a.action
}

// GetObject returns ability object
func (a myAbility) GetObject() string {
	return a.object
}

func TestAuthorizationCheck(t *testing.T) {
	matcher := NewMatcher()
	t.Run("valid ability", func(t *testing.T) {
		if (!AuthorizationCheck(matcher, "foo", "bar", myAbility{"foo", "bar"})) {
			t.Fatal("unexpected result")
		}

		if (!AuthorizationCheck(matcher, "foo", "bar", myAbility{"foo", "bar*"})) {
			t.Fatal("unexpected result")
		}

		if (!AuthorizationCheck(matcher, "foo", "bar", myAbility{"foo*", "bar"})) {
			t.Fatal("unexpected result")
		}

		if (!AuthorizationCheck(matcher, "foo", "bar", myAbility{"foo*", "bar*"})) {
			t.Fatal("unexpected result")
		}

		if (AuthorizationCheck(matcher, "", "bar", myAbility{"foo", "bar"})) {
			t.Fatal("unexpected result")
		}

		if (AuthorizationCheck(matcher, "foo", "", myAbility{"foo", "bar"})) {
			t.Fatal("unexpected result")
		}
	})

	t.Run("invalid ability", func(t *testing.T) {
		if (AuthorizationCheck(matcher, "foo", "bar", myAbility{"", "qux"})) {
			t.Fatal("unexpected result")
		}

		if (AuthorizationCheck(matcher, "foo", "bar", myAbility{"qux", ""})) {
			t.Fatal("unexpected result")
		}
	})
}

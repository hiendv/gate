package internal

// Ability is the contract for user abilities to be checked
type Ability interface {
	GetAction() string
	GetObject() string
}

// AuthorizationCheck performs the check for an action on object with a given ability and a matcher
func AuthorizationCheck(matcher Matcher, action, object string, ability Ability) bool {
	if ability.GetAction() == "" {
		return false
	}

	if ability.GetObject() == "" {
		return false
	}

	actionMatch, err := matcher.Match(action, ability.GetAction())
	if err != nil || !actionMatch {
		return false
	}

	objectMatch, err := matcher.Match(object, ability.GetObject())
	if err != nil || !objectMatch {
		return false
	}

	return true
}

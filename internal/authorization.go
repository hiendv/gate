package internal

type Ability interface {
	GetAction() string
	GetObject() string
}

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

package internal

import (
	"regexp"
	"sync"

	"github.com/pkg/errors"
)

// ErrInvalidExpression is thrown when the given expression is invalid
var ErrInvalidExpression = errors.New("invalid expression")

// AsteriskParse translates asterisk "*" into "(.{0,})" for convenience
func AsteriskParse(exp string) (result string) {
	re := regexp.MustCompile(`\*($|\/)`)
	result = re.ReplaceAllString(exp, "(.{0,})$1")
	return
}

// Matcher performs match operations for the given string and pattern with caching support
type Matcher struct {
	expressions map[string]*regexp.Regexp
	*sync.RWMutex
}

func (service Matcher) getExpression(key string) (expression *regexp.Regexp, err error) {
	expression, ok := service.expressions[key]
	if !ok {
		expression, err = regexp.Compile(AsteriskParse(key))
		if err != nil {
			return
		}

		service.expressions[key] = expression
	}

	if expression == nil {
		err = errors.New("invalid expression")
		return
	}

	return
}

// Match performs the match operation
func (service Matcher) Match(str, pattern string) (match bool, err error) {
	service.Lock()
	defer service.Unlock()

	expression, err := service.getExpression(pattern)
	if err != nil {
		return
	}

	match = expression.MatchString(str)
	return
}

// NewMatcher is the constructor for Matcher
func NewMatcher() Matcher {
	return Matcher{
		expressions: map[string]*regexp.Regexp{},
		RWMutex:     &sync.RWMutex{},
	}
}

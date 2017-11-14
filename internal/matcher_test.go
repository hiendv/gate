package internal

import (
	"regexp"
	"sync"
	"testing"
)

func assertMatch(t *testing.T, matcher Matcher, input, pattern string) {
	match, err := matcher.Match(input, pattern)
	if err != nil || !match {
		t.Fatal("unexpectedly mismatch")
	}
}

func assertMismatch(t *testing.T, matcher Matcher, input, pattern string) {
	match, err := matcher.Match(input, pattern)
	if err == nil && match {
		t.Fatal("unexpectedly match")
	}
}

func TestMatcher(t *testing.T) {
	t.Run("matcher", func(t *testing.T) {
		matcher := NewMatcher()
		assertMatch(t, matcher, "foobar", "*")
		assertMatch(t, matcher, "qux", "*")
		assertMatch(t, matcher, "foobar", "foobar")
		assertMatch(t, matcher, "foobar", "foobar*")

		assertMismatch(t, matcher, "qux", "foobar")
		assertMismatch(t, matcher, "qux", "foobar*")

		assertMismatch(t, matcher, "qux", "(")

		t.Run("with existing expressions", func(t *testing.T) {

			matcher = Matcher{
				expressions: map[string]*regexp.Regexp{
					"foobar": nil,
				},
				RWMutex: &sync.RWMutex{},
			}

			assertMismatch(t, matcher, "foobar", "foobar")
		})
	})
}

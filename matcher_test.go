package gate

import (
	"testing"
)

func TestMatcher(t *testing.T) {
	t.Run("matcher", func(t *testing.T) {
		var match bool
		var err error

		matcher := NewMatcher()

		match, err = matcher.Match("foobar", "*")
		if !match || err != nil {
			t.Fatal("incorrect assertion")
		}

		match, err = matcher.Match("qux", "*")
		if !match || err != nil {
			t.Fatal("incorrect assertion")
		}

		match, err = matcher.Match("foobar", "foobar")
		if !match || err != nil {
			t.Fatal("incorrect assertion")
		}

		match, err = matcher.Match("foobar", "foobar*")
		if !match || err != nil {
			t.Fatal("incorrect assertion")
		}

		match, err = matcher.Match("qux", "foobar")
		if err == nil && match {
			t.Fatal("incorrect assertion")
		}

		match, err = matcher.Match("qux", "foobar*")
		if err == nil && match {
			t.Fatal("incorrect assertion")
		}
	})
}

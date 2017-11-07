package gate

import (
	"fmt"
)

func ExampleMatcher() {
	matcher := NewMatcher()

	fmt.Println(matcher.Match("foobar", "*"))
	fmt.Println(matcher.Match("qux", "*"))
	fmt.Println(matcher.Match("foobar", "foobar"))
	fmt.Println(matcher.Match("foobar", "foobar*"))
	fmt.Println(matcher.Match("qux", "foobar"))
	fmt.Println(matcher.Match("qux", "foobar*"))

	fmt.Println(matcher.Match("foobar", `(\w+)`))
	fmt.Println(matcher.Match("foobar", `(\d+)`))

	fmt.Println(matcher.Match("path/to/something", `path*`))
	fmt.Println(matcher.Match("path/to/something", `path/*`))
	fmt.Println(matcher.Match("path/to/something", `path/*/something`))

	// Output:
	// true <nil>
	// true <nil>
	// true <nil>
	// true <nil>
	// false <nil>
	// false <nil>
	// true <nil>
	// false <nil>
	// true <nil>
	// true <nil>
	// true <nil>
}

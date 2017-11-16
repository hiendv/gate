package test

import (
	"testing"
)

// AssertOK raises a fatal error if the given error is not nil
func AssertOK(t *testing.T, err error, assumption string) {
	if err != nil {
		t.Fatalf("unexpected error: %s, assumption: %s", err, assumption)
	}
}

// AssertErr raises a fatal error if the given error is nil
func AssertErr(t *testing.T, err error, assumption string) {
	if err == nil {
		t.Fatalf("unexpected success, assumption: %s", assumption)
	}
}

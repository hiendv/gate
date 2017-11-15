package test

import (
	"testing"
)

func AssertOK(t *testing.T, err error, assumption string) {
	if err != nil {
		t.Fatalf("unexpected error: %s, assumption: %s", err, assumption)
	}
}

func AssertErr(t *testing.T, err error, assumption string) {
	if err == nil {
		t.Fatalf("unexpected success, assumption: %s", assumption)
	}
}

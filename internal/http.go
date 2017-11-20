package internal

import (
	"net/http"
)

// HTTPClient is the interface for the common HTTP client
type HTTPClient interface {
	Get(url string) (resp *http.Response, err error)
}

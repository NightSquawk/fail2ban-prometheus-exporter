package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
)

func NewBasicAuthProvider(username, password string) AuthProvider {
	return &basicAuthProvider{
		hashedAuth: encodeBasicAuth(username, password),
	}
}

type basicAuthProvider struct {
	hashedAuth string
}

func (p *basicAuthProvider) IsAllowed(request *http.Request) bool {
	username, password, ok := request.BasicAuth()
	if !ok {
		return false
	}
	requestAuth := encodeBasicAuth(username, password)
	// Constant-time comparison: the configured and supplied credentials are
	// hashed to a fixed-length digest first (see encodeBasicAuth/HashString),
	// then compared with subtle.ConstantTimeCompare instead of `==` so the
	// comparison does not leak timing information about how many leading
	// bytes matched.
	return subtle.ConstantTimeCompare([]byte(p.hashedAuth), []byte(requestAuth)) == 1
}

func encodeBasicAuth(username, password string) string {
	return HashString(fmt.Sprintf("%s:%s", username, password))
}

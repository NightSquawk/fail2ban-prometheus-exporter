package server

import (
	"net/http"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/auth"
)

// AuthMiddleware implements the deprecated --web.basic-auth.* flags. When
// --web.config-file is used instead, the auth provider is the empty one and
// exporter-toolkit performs authentication before the request reaches here.
func AuthMiddleware(handlerFunc http.Handler, authProvider auth.AuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authProvider.IsAllowed(r) {
			handlerFunc.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

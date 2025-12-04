package middleware

import (
	"net/http"
	"net/url"
	"todo-app/backend/handlers"
)

// RequireLocalAuth requires local username/password authentication (for admin interface)
func RequireLocalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := handlers.Store.Get(r, "session")
		authMethod, _ := session.Values["auth_method"].(string)

		user := handlers.GetCurrentUser(r)
		if user == nil || authMethod != "local" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// RequireProxyAuth requires SAML authentication (for reverse proxy)
func RequireProxyAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := handlers.Store.Get(r, "session")
		authMethod, _ := session.Values["auth_method"].(string)

		user := handlers.GetCurrentUser(r)
		if user == nil || authMethod != "saml" {
			// Store the original URL to redirect back after SAML auth
			redirectURL := "/saml/login?redirect=" + url.QueryEscape(r.URL.Path)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}


package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// CSRFProtection provides CSRF token validation
type CSRFProtection struct {
	secret []byte
}

// NewCSRFProtection creates a new CSRF protection middleware
func NewCSRFProtection(secret string) *CSRFProtection {
	return &CSRFProtection{secret: []byte(secret)}
}

// generateToken creates a new CSRF token
func (c *CSRFProtection) generateToken() string {
	// Generate random bytes
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)

	// Create HMAC signature
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(randomBytes)
	signature := mac.Sum(nil)

	// Combine random bytes and signature
	token := append(randomBytes, signature...)
	return base64.URLEncoding.EncodeToString(token)
}

// validateToken checks if a token is valid
func (c *CSRFProtection) validateToken(token string) bool {
	if token == "" {
		return false
	}

	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil || len(decoded) < 64 {
		return false
	}

	randomBytes := decoded[:32]
	providedSig := decoded[32:]

	// Recreate expected signature
	mac := hmac.New(sha256.New, c.secret)
	mac.Write(randomBytes)
	expectedSig := mac.Sum(nil)

	return hmac.Equal(providedSig, expectedSig)
}

// Protect wraps a handler with CSRF protection
func (c *CSRFProtection) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe methods don't need CSRF validation, but set token
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			// Set CSRF token cookie if not present
			if _, err := r.Cookie("_csrf"); err != nil {
				token := c.generateToken()
				http.SetCookie(w, &http.Cookie{
					Name:     "_csrf",
					Value:    token,
					Path:     "/",
					HttpOnly: false, // JavaScript needs to read this
					SameSite: http.SameSiteStrictMode,
					Secure:   true,
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods, validate token
		cookieToken, err := r.Cookie("_csrf")
		if err != nil {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		// Get token from form or header
		formToken := r.FormValue("_csrf")
		if formToken == "" {
			formToken = r.Header.Get("X-CSRF-Token")
		}

		// Validate that form token matches cookie token and is valid
		if formToken != cookieToken.Value || !c.validateToken(formToken) {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ProtectFunc wraps a HandlerFunc
func (c *CSRFProtection) ProtectFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.Protect(next).ServeHTTP(w, r)
	}
}




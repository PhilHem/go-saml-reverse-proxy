package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RED: Test that POST without CSRF token is rejected
func TestCSRF_RejectsWithoutToken(t *testing.T) {
	csrf := NewCSRFProtection("test-secret-key-32-chars-long!!!")

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/form", strings.NewReader("data=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token should be rejected, got %d", rec.Code)
	}
}

// RED: Test that POST with valid CSRF token is allowed
func TestCSRF_AllowsWithValidToken(t *testing.T) {
	csrf := NewCSRFProtection("test-secret-key-32-chars-long!!!")

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First, get a token by making a GET request
	getReq := httptest.NewRequest("GET", "/form", nil)
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)

	// Extract token from cookie
	var token string
	for _, c := range getRec.Result().Cookies() {
		if c.Name == "_csrf" {
			token = c.Value
			break
		}
	}

	if token == "" {
		t.Fatal("No CSRF token cookie set")
	}

	// Make POST with token
	postReq := httptest.NewRequest("POST", "/form", strings.NewReader("_csrf="+token))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range getRec.Result().Cookies() {
		postReq.AddCookie(c)
	}
	postRec := httptest.NewRecorder()

	handler.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF token should be allowed, got %d", postRec.Code)
	}
}

// RED: Test that GET requests are not protected (but get token set)
func TestCSRF_GETNotProtected(t *testing.T) {
	csrf := NewCSRFProtection("test-secret-key-32-chars-long!!!")

	handler := csrf.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/page", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET should not require CSRF token, got %d", rec.Code)
	}
}




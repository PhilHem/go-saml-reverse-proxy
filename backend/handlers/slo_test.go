package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"todo-app/backend/models"
)

// Test that SLO endpoint redirects (to IDP if configured, otherwise to /login)
func TestSLO_InitiatesLogout(t *testing.T) {
	// Create request to SLO endpoint
	req := httptest.NewRequest("GET", "/saml/logout", nil)
	rec := httptest.NewRecorder()

	// Call SLO handler (SamlMiddleware is nil in test, so redirects to /login)
	SAMLLogout(rec, req)

	// Should redirect (302 or 303)
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Errorf("Expected redirect (302/303), got %d", rec.Code)
	}

	// Should redirect to /login when SAML not configured
	location := rec.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Expected redirect to /login, got %s", location)
	}
}

// RED: Test that SLO clears local session
func TestSLO_ClearsSession(t *testing.T) {
	// Setup: create a session
	user := &models.User{Email: "test@example.com"}
	user.ID = 1

	req := httptest.NewRequest("GET", "/saml/logout", nil)
	rec := httptest.NewRecorder()

	// Set session first
	session, _ := Store.Get(req, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Save(req, rec)

	// Get cookies and make new request
	req2 := httptest.NewRequest("GET", "/saml/logout", nil)
	for _, c := range rec.Result().Cookies() {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()

	// Call SLO handler
	SAMLLogout(rec2, req2)

	// Verify session is cleared (cookie should be invalidated)
	cookies := rec2.Result().Cookies()
	sessionCleared := false
	for _, c := range cookies {
		if c.Name == "session" && c.MaxAge < 0 {
			sessionCleared = true
		}
	}
	if !sessionCleared {
		t.Error("Session should be cleared after SLO")
	}
}


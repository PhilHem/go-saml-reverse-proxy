package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
)

// Test 1: Proxy blocks unauthenticated requests
func TestProxy_BlocksUnauthenticated(t *testing.T) {
	// Setup test upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Upstream should NOT have been called for unauthenticated request")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Configure proxy
	config.C.Upstream = upstream.URL
	if err := InitProxy(); err != nil {
		t.Fatal(err)
	}

	// Make request without session
	req := httptest.NewRequest("GET", "/proxy/test", nil)
	rec := httptest.NewRecorder()

	Proxy(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized, got %d", rec.Code)
	}
}

// Test 2a: Header injection - X-Forwarded-User is set
func TestProxy_InjectsUserHeader(t *testing.T) {
	var capturedHeaders http.Header

	// Setup test upstream that captures headers
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Configure proxy
	config.C.Upstream = upstream.URL
	if err := InitProxy(); err != nil {
		t.Fatal(err)
	}

	// Setup test user
	user := &models.User{Email: "test@example.com"}
	user.ID = 1

	// Mock GetCurrentUser to return our test user
	origGetUser := GetCurrentUser
	GetCurrentUser = func(r *http.Request) *models.User {
		return user
	}
	defer func() { GetCurrentUser = origGetUser }()

	// Create request
	req := httptest.NewRequest("GET", "/proxy/test", nil)
	rec := httptest.NewRecorder()

	Proxy(rec, req)

	// Verify header was injected
	if capturedHeaders.Get("X-Forwarded-User") != "test@example.com" {
		t.Errorf("Expected X-Forwarded-User=test@example.com, got %s", capturedHeaders.Get("X-Forwarded-User"))
	}
	if capturedHeaders.Get("X-Forwarded-Email") != "test@example.com" {
		t.Errorf("Expected X-Forwarded-Email=test@example.com, got %s", capturedHeaders.Get("X-Forwarded-Email"))
	}
}

// Test 2b: Spoofed headers are stripped
func TestProxy_StripsSpoofedHeaders(t *testing.T) {
	var capturedHeaders http.Header

	// Setup test upstream that captures headers
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Configure proxy
	config.C.Upstream = upstream.URL
	if err := InitProxy(); err != nil {
		t.Fatal(err)
	}

	// Setup test user
	user := &models.User{Email: "test@example.com"}
	user.ID = 1

	// Mock GetCurrentUser
	origGetUser := GetCurrentUser
	GetCurrentUser = func(r *http.Request) *models.User {
		return user
	}
	defer func() { GetCurrentUser = origGetUser }()

	// Create request WITH spoofed headers
	req := httptest.NewRequest("GET", "/proxy/test", nil)
	req.Header.Set("X-Forwarded-User", "attacker@evil.com")
	req.Header.Set("X-Forwarded-Email", "attacker@evil.com")
	rec := httptest.NewRecorder()

	Proxy(rec, req)

	// Verify spoofed headers were replaced with real user
	if capturedHeaders.Get("X-Forwarded-User") != "test@example.com" {
		t.Errorf("Spoofed header not stripped! Got X-Forwarded-User=%s, expected test@example.com",
			capturedHeaders.Get("X-Forwarded-User"))
	}
}

// Test 3: Session grants access after auth
func TestSession_GrantsAccess(t *testing.T) {
	upstreamCalled := false

	// Setup test upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Configure proxy
	config.C.Upstream = upstream.URL
	if err := InitProxy(); err != nil {
		t.Fatal(err)
	}

	// Setup test user
	user := &models.User{Email: "test@example.com"}
	user.ID = 1

	// Mock GetCurrentUser to return user (simulating valid session)
	origGetUser := GetCurrentUser
	GetCurrentUser = func(r *http.Request) *models.User {
		return user
	}
	defer func() { GetCurrentUser = origGetUser }()

	// Make request
	req := httptest.NewRequest("GET", "/proxy/test", nil)
	rec := httptest.NewRecorder()

	Proxy(rec, req)

	if !upstreamCalled {
		t.Error("Upstream should have been called for authenticated request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}
}


package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
)

// RED: Test that IDP-initiated SSO is disabled by default
func TestSAML_IDPInitiatedDisabled(t *testing.T) {
	// Reset config to defaults
	config.C = config.Config{}
	if err := config.Load(); err != nil {
		t.Fatal(err)
	}

	if config.C.SAML.AllowIDPInitiated {
		t.Error("IDP-initiated SSO should be disabled by default")
	}
}

// RED: Test that open redirects are blocked
func TestSAML_BlocksExternalRedirect(t *testing.T) {
	// Test with absolute external URL
	externalURL := "https://evil.com/phish"

	if ValidateRedirect(externalURL) {
		t.Error("External absolute URLs should be rejected")
	}
}

// RED: Test that protocol-relative URLs are blocked
func TestSAML_BlocksProtocolRelativeRedirect(t *testing.T) {
	protocolRelative := "//evil.com/phish"

	if ValidateRedirect(protocolRelative) {
		t.Error("Protocol-relative URLs should be rejected")
	}
}

// RED: Test that relative paths are allowed
func TestSAML_AllowsRelativePath(t *testing.T) {
	relativePath := "/dashboard"

	if !ValidateRedirect(relativePath) {
		t.Error("Relative paths should be allowed")
	}
}

// RED: Test that same-origin absolute URLs are allowed
func TestSAML_AllowsSameOriginAbsolute(t *testing.T) {
	config.C.PublicURL = "https://proxy.example.com"
	sameOrigin := "https://proxy.example.com/dashboard"

	if !ValidateRedirect(sameOrigin) {
		t.Error("Same-origin absolute URLs should be allowed")
	}
}

// RED: Test that error responses don't leak internal details
func TestSAML_ErrorResponseNoDetails(t *testing.T) {
	// Skip if SAML middleware not initialized
	if SamlMiddleware == nil {
		t.Skip("SAML middleware not initialized")
	}

	req := httptest.NewRequest("POST", "/saml/acs", strings.NewReader("SAMLResponse=invalid"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	SAMLACS(rec, req)

	body := rec.Body.String()
	// Should NOT contain internal error details
	if strings.Contains(body, "cannot unmarshal") ||
		strings.Contains(body, "parse") ||
		strings.Contains(body, "invalid") {
		t.Error("Error response should not contain internal error details")
	}
}

// RED: Test that redirect URL is validated in SAMLLogin
func TestSAMLLogin_ValidatesRedirect(t *testing.T) {
	// Skip if SAML middleware not initialized (will test validation logic directly)
	if SamlMiddleware == nil {
		t.Skip("SAML middleware not initialized")
	}

	req := httptest.NewRequest("GET", "/saml/login?redirect=https://evil.com/phish", nil)
	rec := httptest.NewRecorder()

	// Get session to check if redirect was stored
	SAMLLogin(rec, req)

	session, _ := Store.Get(req, "session")
	redirect, _ := session.Values["saml_redirect"].(string)

	// External redirect should not be stored
	if redirect == "https://evil.com/phish" {
		t.Error("External redirect URL should not be stored in session")
	}
}

// RED: Test email domain allowlist - allowed domain
func TestSAML_AllowedDomain(t *testing.T) {
	config.C.SAML.AllowedDomains = []string{"example.com", "corp.example.com"}

	if !IsEmailDomainAllowed("user@example.com") {
		t.Error("Email from allowed domain should be accepted")
	}
	if !IsEmailDomainAllowed("user@corp.example.com") {
		t.Error("Email from allowed subdomain should be accepted")
	}
}

// RED: Test email domain allowlist - blocked domain
func TestSAML_BlockedDomain(t *testing.T) {
	config.C.SAML.AllowedDomains = []string{"example.com"}

	if IsEmailDomainAllowed("user@evil.com") {
		t.Error("Email from non-allowed domain should be rejected")
	}
}

// RED: Test email domain allowlist - empty allowlist allows all
func TestSAML_EmptyAllowlistAllowsAll(t *testing.T) {
	config.C.SAML.AllowedDomains = []string{}

	if !IsEmailDomainAllowed("user@any-domain.com") {
		t.Error("Empty allowlist should allow all domains")
	}
}

// RED: Test fetchIDPMetadata with single entity descriptor
func TestFetchIDPMetadata_SingleEntity(t *testing.T) {
	// Single entity metadata (like from npx saml-idp)
	singleEntityXML := `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

	entity, err := parseIDPMetadata([]byte(singleEntityXML), "")
	if err != nil {
		t.Fatalf("Failed to parse single entity metadata: %v", err)
	}
	if entity.EntityID != "https://idp.example.com" {
		t.Errorf("Expected entity ID https://idp.example.com, got %s", entity.EntityID)
	}
}

// RED: Test fetchIDPMetadata with federation metadata and entity ID filter
func TestFetchIDPMetadata_FederationWithEntityID(t *testing.T) {
	// Federation metadata with multiple entities
	federationXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="Test Federation">
  <EntityDescriptor entityID="https://idp1.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp2.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

	// Should find the second entity by ID
	entity, err := parseIDPMetadata([]byte(federationXML), "https://idp2.example.com")
	if err != nil {
		t.Fatalf("Failed to parse federation metadata: %v", err)
	}
	if entity.EntityID != "https://idp2.example.com" {
		t.Errorf("Expected entity ID https://idp2.example.com, got %s", entity.EntityID)
	}
}

// RED: Test fetchIDPMetadata with federation metadata returns first IDP when no entity ID
func TestFetchIDPMetadata_FederationNoEntityID(t *testing.T) {
	federationXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="Test Federation">
  <EntityDescriptor entityID="https://idp1.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp2.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

	// Empty entity ID should return first IDP
	entity, err := parseIDPMetadata([]byte(federationXML), "")
	if err != nil {
		t.Fatalf("Failed to parse federation metadata: %v", err)
	}
	if entity.EntityID != "https://idp1.example.com" {
		t.Errorf("Expected first entity ID https://idp1.example.com, got %s", entity.EntityID)
	}
}

// RED: Test fetchIDPMetadata returns error when entity ID not found
func TestFetchIDPMetadata_EntityNotFound(t *testing.T) {
	federationXML := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="Test Federation">
  <EntityDescriptor entityID="https://idp1.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

	_, err := parseIDPMetadata([]byte(federationXML), "https://nonexistent.example.com")
	if err == nil {
		t.Error("Expected error when entity ID not found")
	}
}

// Test that SLO endpoint redirects (to IDP if configured, otherwise to /login)
func TestSLO_InitiatesLogout(t *testing.T) {
	// Initialize session store
	config.C.Session.Secret = "test-secret-key-32-chars-long!!!"
	if err := InitSession(); err != nil {
		t.Fatal(err)
	}

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
	// Initialize session store
	config.C.Session.Secret = "test-secret-key-32-chars-long!!!"
	if err := InitSession(); err != nil {
		t.Fatal(err)
	}

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


package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// ValidateRedirect checks if a redirect URL is safe (relative or same-origin)
func ValidateRedirect(redirect string) bool {
	if redirect == "" {
		return true
	}

	// Block protocol-relative URLs
	if strings.HasPrefix(redirect, "//") {
		return false
	}

	// Allow relative paths
	if strings.HasPrefix(redirect, "/") {
		return true
	}

	// Check if absolute URL matches public URL origin
	parsed, err := url.Parse(redirect)
	if err != nil {
		return false
	}

	publicURL, err := url.Parse(config.C.PublicURL)
	if err != nil {
		return false
	}

	return parsed.Scheme == publicURL.Scheme && parsed.Host == publicURL.Host
}

// IsEmailDomainAllowed checks if an email's domain is in the allowlist
func IsEmailDomainAllowed(email string) bool {
	// Empty allowlist means all domains are allowed
	if len(config.C.SAML.AllowedDomains) == 0 {
		return true
	}

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	// Check against allowlist
	for _, allowed := range config.C.SAML.AllowedDomains {
		if strings.ToLower(allowed) == domain {
			return true
		}
	}
	return false
}

var SamlMiddleware *samlsp.Middleware

// parseIDPMetadata parses SAML metadata XML and optionally filters by entity ID.
// Supports both single EntityDescriptor and federation EntitiesDescriptor formats.
func parseIDPMetadata(data []byte, entityID string) (*saml.EntityDescriptor, error) {
	// Try parsing as single EntityDescriptor first
	var entity saml.EntityDescriptor
	if err := xml.Unmarshal(data, &entity); err == nil && entity.EntityID != "" {
		// Check if entity ID matches (or no filter specified)
		if entityID == "" || entity.EntityID == entityID {
			return &entity, nil
		}
		return nil, fmt.Errorf("entity ID mismatch: got %s, want %s", entity.EntityID, entityID)
	}

	// Try parsing as EntitiesDescriptor (federation metadata)
	var entities saml.EntitiesDescriptor
	if err := xml.Unmarshal(data, &entities); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// Find matching entity
	for i := range entities.EntityDescriptors {
		e := &entities.EntityDescriptors[i]
		// Skip non-IDP entities
		if len(e.IDPSSODescriptors) == 0 {
			continue
		}
		// Return first IDP if no entity ID specified
		if entityID == "" {
			return e, nil
		}
		// Return matching entity
		if e.EntityID == entityID {
			return e, nil
		}
	}

	if entityID == "" {
		return nil, fmt.Errorf("no IDP found in metadata")
	}
	return nil, fmt.Errorf("IDP with entity ID %q not found in metadata", entityID)
}

// fetchIDPMetadata fetches and parses IDP metadata from a URL with optional entity ID filter.
func fetchIDPMetadata(ctx context.Context, httpClient *http.Client, metadataURL string, entityID string) (*saml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetching metadata: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}

	return parseIDPMetadata(data, entityID)
}

func InitSAML() error {
	// Load SP certificate and key
	keyPair, err := tls.LoadX509KeyPair(config.C.SAML.SPCert, config.C.SAML.SPKey)
	if err != nil {
		slog.Error("SAML init failed: certificate load error", "source", "saml", "error", err.Error())
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		slog.Error("SAML init failed: certificate parse error", "source", "saml", "error", err.Error())
		return err
	}

	// Fetch IDP metadata with optional entity ID filter (for federation metadata)
	idpMetadata, err := fetchIDPMetadata(context.Background(), http.DefaultClient, config.C.SAML.IDPMetadataURL, config.C.SAML.IDPEntityID)
	if err != nil {
		slog.Error("SAML init failed: IDP metadata fetch error", "source", "saml", "error", err.Error())
		return err
	}
	if config.C.SAML.IDPEntityID != "" {
		slog.Info("Using IDP from federation metadata", "source", "saml", "entity_id", idpMetadata.EntityID)
	}

	// SP root URL - use public URL for SAML (what's exposed via reverse proxy)
	rootURL, _ := url.Parse(config.C.PublicURL)

	SamlMiddleware, err = samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: config.C.SAML.AllowIDPInitiated,
	})
	if err != nil {
		slog.Error("SAML init failed: middleware creation error", "source", "saml", "error", err.Error())
	} else {
		slog.Info("SAML initialized successfully", "source", "saml")
	}
	return err
}

// SAMLMetadata serves the SP metadata
func SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	SamlMiddleware.ServeMetadata(w, r)
}

// SAMLLogin initiates the SAML auth flow
func SAMLLogin(w http.ResponseWriter, r *http.Request) {
	// Store redirect URL in session for post-auth redirect (validate first)
	redirect := r.URL.Query().Get("redirect")
	if redirect != "" && ValidateRedirect(redirect) {
		session, _ := Store.Get(r, "session")
		session.Values["saml_redirect"] = redirect
		session.Save(r, w)
	} else if redirect != "" {
		slog.Warn("SAML login rejected invalid redirect", "source", "saml", "redirect", redirect)
	}

	slog.Info("SAML login initiated", "source", "saml", "redirect", redirect)
	SamlMiddleware.HandleStartAuthFlow(w, r)
}

// SAMLACS handles the SAML assertion callback and creates app session
func SAMLACS(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		slog.Warn("SAML ACS failed: bad request", "source", "saml", "error", err.Error())
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Use AllowIDPInitiated mode based on config
	// Extract possible request IDs from tracking cookies
	var possibleRequestIDs []string
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "saml_") {
			possibleRequestIDs = append(possibleRequestIDs, strings.TrimPrefix(cookie.Name, "saml_"))
		}
	}
	
	assertion, err := SamlMiddleware.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		slog.Warn("SAML ACS failed: assertion parse error", "source", "saml", "error", fmt.Sprintf("%+v", err), "request_ids", possibleRequestIDs)
		http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Get email from SAML attributes or NameID
	var email string
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name == "email" || attr.FriendlyName == "email" {
				if len(attr.Values) > 0 {
					email = attr.Values[0].Value
				}
			}
		}
	}
	if email == "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		email = assertion.Subject.NameID.Value
	}

	if email == "" {
		slog.Warn("SAML ACS failed: no email in response", "source", "saml")
		http.Error(w, "No email in SAML response", http.StatusUnauthorized)
		return
	}

	// Check if email domain is allowed
	if !IsEmailDomainAllowed(email) {
		slog.Warn("SAML ACS failed: email domain not allowed", "source", "saml", "email", email)
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Find or create user
	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		// Create user if doesn't exist (SSO auto-provision)
		user = models.User{Email: email, Password: ""}
		database.DB.Create(&user)
		slog.Info("user auto-provisioned via SAML", "source", "saml", "user_id", user.ID, "email", email)
	}

	// Create app session
	session, _ := Store.Get(r, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "saml"

	// Get redirect URL if set during login initiation
	redirect, _ := session.Values["saml_redirect"].(string)
	delete(session.Values, "saml_redirect")
	session.Save(r, w)

	slog.Info("user logged in via SAML", "source", "saml", "user_id", user.ID, "email", email)

	// Redirect to original URL or root (proxy)
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// SAMLLogout handles SP-initiated Single Logout
func SAMLLogout(w http.ResponseWriter, r *http.Request) {
	// Get current session to log user info
	session, _ := Store.Get(r, "session")
	userID, _ := session.Values["user_id"].(uint)
	email, _ := session.Values["email"].(string)

	slog.Info("SAML logout initiated", "source", "saml", "user_id", userID, "email", email)

	// Clear local session first
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Check if SAML is configured and IDP supports SLO
	if SamlMiddleware != nil &&
		len(SamlMiddleware.ServiceProvider.IDPMetadata.IDPSSODescriptors) > 0 {
		idpDesc := SamlMiddleware.ServiceProvider.IDPMetadata.IDPSSODescriptors[0]
		if len(idpDesc.SingleLogoutServices) > 0 {
			// Redirect to IDP's SLO endpoint
			sloURL := idpDesc.SingleLogoutServices[0].Location
			slog.Info("redirecting to IDP SLO", "source", "saml", "slo_url", sloURL)
			http.Redirect(w, r, sloURL, http.StatusFound)
			return
		}
	}

	// IDP doesn't support SLO or SAML not configured, just redirect to login
	slog.Info("IDP does not support SLO, redirecting to login", "source", "saml")
	http.Redirect(w, r, "/login", http.StatusFound)
}


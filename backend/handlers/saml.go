package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"
	"todo-app/backend/config"
	"todo-app/backend/database"
	"todo-app/backend/models"

	"github.com/crewjam/saml/samlsp"
)

var SamlMiddleware *samlsp.Middleware

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

	// Fetch IDP metadata
	idpMetadataURL, _ := url.Parse(config.C.SAML.IDPMetadataURL)
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		slog.Error("SAML init failed: IDP metadata fetch error", "source", "saml", "error", err.Error())
		return err
	}

	// SP root URL - use public URL for SAML (what's exposed via reverse proxy)
	rootURL, _ := url.Parse(config.C.PublicURL)

	SamlMiddleware, err = samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: true,
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
	// Store redirect URL in session for post-auth redirect
	redirect := r.URL.Query().Get("redirect")
	if redirect != "" {
		session, _ := Store.Get(r, "session")
		session.Values["saml_redirect"] = redirect
		session.Save(r, w)
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

	// Use AllowIDPInitiated mode - pass nil for possibleRequestIDs
	assertion, err := SamlMiddleware.ServiceProvider.ParseResponse(r, nil)
	if err != nil {
		slog.Warn("SAML ACS failed: assertion parse error", "source", "saml", "error", err.Error())
		http.Error(w, "SAML error: "+err.Error(), http.StatusUnauthorized)
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


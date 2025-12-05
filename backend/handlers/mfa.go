package handlers

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"log/slog"
	"net/http"
	"time"

	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
	"github.com/PhilHem/go-saml-reverse-proxy/frontend/templates"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const mfaIssuer = "SAML-Proxy"

// GenerateMFASecret creates a new TOTP key for the given email
func GenerateMFASecret(email string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      mfaIssuer,
		AccountName: email,
	})
}

// ValidateMFACode checks if the provided code is valid for the given secret
func ValidateMFACode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// generateQRCode creates a base64-encoded PNG QR code for the TOTP key
func generateQRCode(key *otp.Key) (string, error) {
	img, err := key.Image(200, 200)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// MFASetupPage displays the 2FA setup page with QR code
func MFASetupPage(w http.ResponseWriter, r *http.Request) {
	user := GetCurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	// Generate new secret
	key, err := GenerateMFASecret(user.Email)
	if err != nil {
		slog.Error("failed to generate MFA secret", "source", "mfa", "error", err.Error())
		http.Error(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
		return
	}

	// Generate QR code
	qrCode, err := generateQRCode(key)
	if err != nil {
		slog.Error("failed to generate QR code", "source", "mfa", "error", err.Error())
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	templates.MFASetup(qrCode, key.Secret(), user.MFAEnabled, "").Render(r.Context(), w)
}

// MFAEnable enables 2FA for the current user after verifying the code
func MFAEnable(w http.ResponseWriter, r *http.Request) {
	user := GetCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	secret := r.FormValue("secret")

	if !ValidateMFACode(secret, code) {
		slog.Warn("MFA enable failed: invalid code", "source", "mfa", "user_id", user.ID)
		templates.MFASetupForm("", secret, false, "Invalid code. Please try again.").Render(r.Context(), w)
		return
	}

	// Update user with MFA enabled
	user.MFAEnabled = true
	user.MFASecret = secret
	if err := database.DB.Save(user).Error; err != nil {
		slog.Error("failed to enable MFA", "source", "mfa", "user_id", user.ID, "error", err.Error())
		templates.MFASetupForm("", secret, false, "Failed to enable 2FA").Render(r.Context(), w)
		return
	}

	slog.Info("MFA enabled", "source", "mfa", "user_id", user.ID)

	// Regenerate QR code for the response (in case they want to re-scan)
	key, _ := GenerateMFASecret(user.Email)
	qrCode, _ := generateQRCode(key)

	templates.MFASetupForm(qrCode, key.Secret(), true, "").Render(r.Context(), w)
}

// MFADisable disables 2FA for the current user after verifying the code
func MFADisable(w http.ResponseWriter, r *http.Request) {
	user := GetCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")

	if !ValidateMFACode(user.MFASecret, code) {
		slog.Warn("MFA disable failed: invalid code", "source", "mfa", "user_id", user.ID)
		// Generate new QR code for the form
		key, _ := GenerateMFASecret(user.Email)
		qrCode, _ := generateQRCode(key)
		templates.MFASetupForm(qrCode, key.Secret(), true, "Invalid code. Please try again.").Render(r.Context(), w)
		return
	}

	// Clear MFA settings
	user.MFAEnabled = false
	user.MFASecret = ""
	if err := database.DB.Save(user).Error; err != nil {
		slog.Error("failed to disable MFA", "source", "mfa", "user_id", user.ID, "error", err.Error())
		key, _ := GenerateMFASecret(user.Email)
		qrCode, _ := generateQRCode(key)
		templates.MFASetupForm(qrCode, key.Secret(), true, "Failed to disable 2FA").Render(r.Context(), w)
		return
	}

	slog.Info("MFA disabled", "source", "mfa", "user_id", user.ID)

	// Generate new QR code for setup form
	key, _ := GenerateMFASecret(user.Email)
	qrCode, _ := generateQRCode(key)

	templates.MFASetupForm(qrCode, key.Secret(), false, "").Render(r.Context(), w)
}

// MFAVerifyPage displays the 2FA verification page during login
func MFAVerifyPage(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session")

	// Check if user is in pending MFA state
	userID, ok := session.Values["user_id_pending_mfa"].(uint)
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	// Verify user exists
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	templates.MFAVerify("").Render(r.Context(), w)
}

// MFAVerify validates the 2FA code and completes login
func MFAVerify(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session")

	// Check if user is in pending MFA state
	userID, ok := session.Values["user_id_pending_mfa"].(uint)
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	// Get user from database
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")

	if !ValidateMFACode(user.MFASecret, code) {
		slog.Warn("MFA verification failed: invalid code", "source", "mfa", "user_id", user.ID)
		templates.MFAVerifyForm("Invalid code. Please try again.").Render(r.Context(), w)
		return
	}

	// Clear pending state and set full session
	delete(session.Values, "user_id_pending_mfa")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"
	session.Values["mfa_verified"] = true
	session.Values["mfa_verified_at"] = time.Now().Unix()
	session.Save(r, w)

	slog.Info("MFA verification successful", "source", "mfa", "user_id", user.ID)

	w.Header().Set("HX-Redirect", "/admin/logs")
	w.WriteHeader(http.StatusOK)
}

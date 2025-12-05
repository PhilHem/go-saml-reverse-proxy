package handlers

import (
	"os"
	"testing"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthTestDB(t *testing.T) {
	var err error
	database.DB, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	database.DB.AutoMigrate(&models.User{}, &models.LogEntry{})
}

// RED: Test that session secret is loaded from config/env, not hardcoded
func TestInitSession_UsesConfigSecret(t *testing.T) {
	// Set session secret via env (must be 32+ chars)
	os.Setenv("SESSION_SECRET", "test-secret-key-32-chars-long!!!")
	defer os.Unsetenv("SESSION_SECRET")

	// Reload config
	if err := config.Load(); err != nil {
		t.Fatal(err)
	}

	// Initialize session
	if err := InitSession(); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	// Verify secret is from config, not hardcoded
	if config.C.Session.Secret == "" {
		t.Error("Session secret should be loaded from config")
	}
	if config.C.Session.Secret == "super-secret-key-change-in-prod" {
		t.Error("Session secret should not be the hardcoded default")
	}
}

// RED: Test that empty session secret causes error
func TestInitSession_FailsOnEmptySecret(t *testing.T) {
	// Clear session secret
	os.Unsetenv("SESSION_SECRET")

	// Reset config to ensure no secret
	config.C.Session.Secret = ""

	err := InitSession()
	if err == nil {
		t.Error("InitSession should fail when session secret is empty")
	}
}

// RED: Test that weak session secret (too short) causes error
func TestInitSession_FailsOnWeakSecret(t *testing.T) {
	// Set a weak/short secret
	os.Setenv("SESSION_SECRET", "short")
	defer os.Unsetenv("SESSION_SECRET")

	if err := config.Load(); err != nil {
		t.Fatal(err)
	}

	err := InitSession()
	if err == nil {
		t.Error("InitSession should fail when session secret is too short")
	}
}

// RED: Test that Secure cookie flag matches TLS config
func TestInitSession_SecureCookieFlag(t *testing.T) {
	os.Setenv("SESSION_SECRET", "test-secret-key-32-chars-long!!!")
	defer os.Unsetenv("SESSION_SECRET")

	if err := config.Load(); err != nil {
		t.Fatal(err)
	}

	if err := InitSession(); err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	// Secure flag should match TLS enabled setting
	if Store.Options.Secure != config.C.TLS.Enabled {
		t.Errorf("Session cookie Secure flag should match TLS.Enabled (got %v, expected %v)", Store.Options.Secure, config.C.TLS.Enabled)
	}
}

// RED: Test password validation - too short
func TestValidatePassword_TooShort(t *testing.T) {
	err := ValidatePassword("Short1!")
	if err == nil {
		t.Error("Password under 8 chars should be rejected")
	}
}

// RED: Test password validation - no uppercase
func TestValidatePassword_NoUppercase(t *testing.T) {
	err := ValidatePassword("password1!")
	if err == nil {
		t.Error("Password without uppercase should be rejected")
	}
}

// RED: Test password validation - no number
func TestValidatePassword_NoNumber(t *testing.T) {
	err := ValidatePassword("Password!")
	if err == nil {
		t.Error("Password without number should be rejected")
	}
}

// RED: Test password validation - no special char
func TestValidatePassword_NoSpecialChar(t *testing.T) {
	err := ValidatePassword("Password1")
	if err == nil {
		t.Error("Password without special char should be rejected")
	}
}

// RED: Test password validation - valid password
func TestValidatePassword_Valid(t *testing.T) {
	err := ValidatePassword("Password1!")
	if err != nil {
		t.Errorf("Valid password should be accepted, got error: %v", err)
	}
}

// RED: Test registration blocked when users already exist
func TestRegister_BlockedWhenUsersExist(t *testing.T) {
	setupAuthTestDB(t)

	// Create an existing user
	database.DB.Create(&models.User{Email: "existing@example.com", Password: "hash"})

	// Try to check if registration is allowed
	if IsRegistrationAllowed() {
		t.Error("Registration should be blocked when users already exist")
	}
}

// RED: Test registration allowed when no users exist
func TestRegister_AllowedWhenNoUsers(t *testing.T) {
	setupAuthTestDB(t)

	// No users - registration should be allowed
	if !IsRegistrationAllowed() {
		t.Error("Registration should be allowed when no users exist")
	}
}

// RED: Test email validation - invalid formats
func TestValidateEmail_Invalid(t *testing.T) {
	invalidEmails := []string{
		"notanemail",
		"missing@domain",
		"@nodomain.com",
		"spaces in@email.com",
		"",
	}

	for _, email := range invalidEmails {
		if ValidateEmail(email) {
			t.Errorf("Email %q should be invalid", email)
		}
	}
}

// RED: Test email validation - valid formats
func TestValidateEmail_Valid(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
	}

	for _, email := range validEmails {
		if !ValidateEmail(email) {
			t.Errorf("Email %q should be valid", email)
		}
	}
}


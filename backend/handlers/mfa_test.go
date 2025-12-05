package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func setupMFATestDB(t *testing.T) {
	setupAuthTestDB(t)
}

// RED: Test TOTP secret generation returns a valid secret
func TestGenerateMFASecret_ReturnsValidSecret(t *testing.T) {
	key, err := GenerateMFASecret("test@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret failed: %v", err)
	}

	if key == nil {
		t.Fatal("GenerateMFASecret returned nil key")
	}

	// Secret should be base32 encoded and non-empty
	if key.Secret() == "" {
		t.Error("Generated secret should not be empty")
	}

	// Should have correct issuer
	if key.Issuer() != "SAML-Proxy" {
		t.Errorf("Expected issuer 'SAML-Proxy', got %q", key.Issuer())
	}

	// Should have correct account name
	if key.AccountName() != "test@example.com" {
		t.Errorf("Expected account 'test@example.com', got %q", key.AccountName())
	}
}

// RED: Test TOTP code validation with a valid code
func TestValidateMFACode_ValidCode(t *testing.T) {
	// Generate a secret
	key, err := GenerateMFASecret("test@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret failed: %v", err)
	}

	// Generate a valid code for the current time
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("Failed to generate TOTP code: %v", err)
	}

	// Validate should succeed
	if !ValidateMFACode(key.Secret(), code) {
		t.Error("ValidateMFACode should return true for valid code")
	}
}

// RED: Test TOTP code validation with an invalid code
func TestValidateMFACode_InvalidCode(t *testing.T) {
	// Generate a secret
	key, err := GenerateMFASecret("test@example.com")
	if err != nil {
		t.Fatalf("GenerateMFASecret failed: %v", err)
	}

	// Use an obviously invalid code
	if ValidateMFACode(key.Secret(), "000000") {
		t.Error("ValidateMFACode should return false for invalid code")
	}

	if ValidateMFACode(key.Secret(), "invalid") {
		t.Error("ValidateMFACode should return false for non-numeric code")
	}
}

// RED: Test MFA enable requires a valid TOTP code
func TestMFAEnable_RequiresValidCode(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create a user
	user := models.User{Email: "test@example.com", Password: "hash"}
	database.DB.Create(&user)

	// Generate a secret and store it in session (simulating setup flow)
	key, _ := GenerateMFASecret(user.Email)

	// Create request with invalid code
	form := url.Values{}
	form.Add("code", "000000")
	form.Add("secret", key.Secret())
	req := httptest.NewRequest("POST", "/admin/2fa/enable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up session with user
	session, _ := Store.Get(req, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	// Copy cookies to request
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFAEnable(rr, req)

	// Should fail - check response contains error
	if rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), "HX-Redirect") {
		t.Error("MFAEnable should fail with invalid code")
	}
}

// RED: Test MFA enable updates user record when code is valid
func TestMFAEnable_UpdatesUserMFAFields(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create a user without MFA
	user := models.User{Email: "test@example.com", Password: "hash", MFAEnabled: false}
	database.DB.Create(&user)

	// Generate a secret
	key, _ := GenerateMFASecret(user.Email)

	// Generate valid code
	code, _ := totp.GenerateCode(key.Secret(), time.Now())

	// Create request with valid code
	form := url.Values{}
	form.Add("code", code)
	form.Add("secret", key.Secret())
	req := httptest.NewRequest("POST", "/admin/2fa/enable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up session with user
	session, _ := Store.Get(req, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFAEnable(rr, req)

	// Check user was updated in DB
	var updatedUser models.User
	database.DB.First(&updatedUser, user.ID)

	if !updatedUser.MFAEnabled {
		t.Error("User MFAEnabled should be true after enabling")
	}
	if updatedUser.MFASecret == "" {
		t.Error("User MFASecret should be set after enabling")
	}
}

// RED: Test MFA disable requires valid code
func TestMFADisable_RequiresValidCode(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create a user with MFA enabled
	key, _ := GenerateMFASecret("test@example.com")
	user := models.User{
		Email:      "test@example.com",
		Password:   "hash",
		MFAEnabled: true,
		MFASecret:  key.Secret(),
	}
	database.DB.Create(&user)

	// Create request with invalid code
	form := url.Values{}
	form.Add("code", "000000")
	req := httptest.NewRequest("POST", "/admin/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up session
	session, _ := Store.Get(req, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFADisable(rr, req)

	// Verify MFA is still enabled
	var updatedUser models.User
	database.DB.First(&updatedUser, user.ID)

	if !updatedUser.MFAEnabled {
		t.Error("MFA should still be enabled after failed disable attempt")
	}
}

// RED: Test MFA disable clears user MFA fields
func TestMFADisable_ClearsUserMFAFields(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create a user with MFA enabled
	key, _ := GenerateMFASecret("test@example.com")
	user := models.User{
		Email:      "test@example.com",
		Password:   "hash",
		MFAEnabled: true,
		MFASecret:  key.Secret(),
	}
	database.DB.Create(&user)

	// Generate valid code
	code, _ := totp.GenerateCode(key.Secret(), time.Now())

	// Create request with valid code
	form := url.Values{}
	form.Add("code", code)
	req := httptest.NewRequest("POST", "/admin/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up session
	session, _ := Store.Get(req, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFADisable(rr, req)

	// Verify MFA is disabled
	var updatedUser models.User
	database.DB.First(&updatedUser, user.ID)

	if updatedUser.MFAEnabled {
		t.Error("MFAEnabled should be false after disabling")
	}
	if updatedUser.MFASecret != "" {
		t.Error("MFASecret should be cleared after disabling")
	}
}

// RED: Test login with MFA enabled sets pending session
func TestLogin_WithMFAEnabled_SetsPendingSession(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create user with MFA enabled
	key, _ := GenerateMFASecret("test@example.com")
	hashedPw, _ := hashPassword("Password1!")
	user := models.User{
		Email:      "test@example.com",
		Password:   hashedPw,
		MFAEnabled: true,
		MFASecret:  key.Secret(),
	}
	database.DB.Create(&user)

	// Create login request
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "Password1!")
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	Login(rr, req)

	// Should redirect to 2FA verify page
	if !strings.Contains(rr.Header().Get("HX-Redirect"), "/admin/2fa/verify") {
		t.Errorf("Expected redirect to /admin/2fa/verify, got %q", rr.Header().Get("HX-Redirect"))
	}

	// Session should have pending flag (check via response cookies)
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("Expected session cookie to be set")
	}
}

// RED: Test login with MFA disabled completes normally
func TestLogin_WithMFADisabled_CompletesNormally(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create user without MFA
	hashedPw, _ := hashPassword("Password1!")
	user := models.User{
		Email:      "test@example.com",
		Password:   hashedPw,
		MFAEnabled: false,
	}
	database.DB.Create(&user)

	// Create login request
	form := url.Values{}
	form.Add("email", "test@example.com")
	form.Add("password", "Password1!")
	req := httptest.NewRequest("POST", "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	Login(rr, req)

	// Should redirect to admin logs (not 2FA verify)
	redirect := rr.Header().Get("HX-Redirect")
	if redirect != "/admin/logs" {
		t.Errorf("Expected redirect to /admin/logs, got %q", redirect)
	}
}

// RED: Test MFA verify with valid code completes login
func TestMFAVerify_ValidCode_CompletesLogin(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create user with MFA enabled
	key, _ := GenerateMFASecret("test@example.com")
	user := models.User{
		Email:      "test@example.com",
		Password:   "hash",
		MFAEnabled: true,
		MFASecret:  key.Secret(),
	}
	database.DB.Create(&user)

	// Generate valid code
	code, _ := totp.GenerateCode(key.Secret(), time.Now())

	// Create verify request
	form := url.Values{}
	form.Add("code", code)
	req := httptest.NewRequest("POST", "/admin/2fa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up pending MFA session
	session, _ := Store.Get(req, "session")
	session.Values["user_id_pending_mfa"] = user.ID
	session.Values["email"] = user.Email

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFAVerify(rr, req)

	// Should redirect to admin logs
	redirect := rr.Header().Get("HX-Redirect")
	if redirect != "/admin/logs" {
		t.Errorf("Expected redirect to /admin/logs after valid code, got %q", redirect)
	}
}

// RED: Test MFA verify with invalid code fails
func TestMFAVerify_InvalidCode_Fails(t *testing.T) {
	setupMFATestDB(t)
	initTestSession(t)

	// Create user with MFA enabled
	key, _ := GenerateMFASecret("test@example.com")
	user := models.User{
		Email:      "test@example.com",
		Password:   "hash",
		MFAEnabled: true,
		MFASecret:  key.Secret(),
	}
	database.DB.Create(&user)

	// Create verify request with invalid code
	form := url.Values{}
	form.Add("code", "000000")
	req := httptest.NewRequest("POST", "/admin/2fa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set up pending MFA session
	session, _ := Store.Get(req, "session")
	session.Values["user_id_pending_mfa"] = user.ID
	session.Values["email"] = user.Email

	rr := httptest.NewRecorder()
	session.Save(req, rr)

	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	rr = httptest.NewRecorder()
	MFAVerify(rr, req)

	// Should NOT redirect to admin logs
	redirect := rr.Header().Get("HX-Redirect")
	if redirect == "/admin/logs" {
		t.Error("Should not redirect to admin logs with invalid code")
	}

	// Body should contain error message
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid") && !strings.Contains(body, "invalid") && !strings.Contains(body, "error") {
		t.Error("Response should contain error message for invalid code")
	}
}

// Helper to init test session store
func initTestSession(t *testing.T) {
	Store = sessions.NewCookieStore([]byte("test-secret-key-32-chars-long!!!"))
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
	}
}

// Helper to hash password for test users
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

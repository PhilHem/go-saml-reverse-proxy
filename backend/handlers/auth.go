package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"
	"github.com/PhilHem/go-saml-reverse-proxy/frontend/templates"
	"unicode"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail checks if email format is valid
func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}
	return emailRegex.MatchString(email)
}

// IsRegistrationAllowed returns true only if no admin users exist (first-user setup)
func IsRegistrationAllowed() bool {
	var count int64
	database.DB.Model(&models.User{}).Count(&count)
	return count == 0
}

var Store *sessions.CookieStore

// InitSession configures the session store with secret and timeout from config
func InitSession() error {
	if config.C.Session.Secret == "" {
		return errors.New("session secret is required")
	}
	if len(config.C.Session.Secret) < 32 {
		return errors.New("session secret must be at least 32 characters")
	}

	Store = sessions.NewCookieStore([]byte(config.C.Session.Secret))
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(config.C.Session.Timeout.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	return nil
}

// ValidatePassword checks password strength requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var hasUpper, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsNumber(c):
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;':\",./<>?", c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	templates.Login("", "").Render(r.Context(), w)
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
	if !IsRegistrationAllowed() {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	templates.Register("", "").Render(r.Context(), w)
}

func Login(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	password := r.FormValue("password")

	var user models.User
	if err := database.DB.Where("email = ?", email).First(&user).Error; err != nil {
		slog.Warn("login failed: user not found", "source", "auth", "email", email)
		templates.LoginForm("Invalid email or password", email).Render(r.Context(), w)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		slog.Warn("login failed: invalid password", "source", "auth", "email", email)
		templates.LoginForm("Invalid email or password", email).Render(r.Context(), w)
		return
	}

	session, _ := Store.Get(r, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"
	session.Save(r, w)

	slog.Info("user logged in", "source", "auth", "user_id", user.ID, "email", email)

	w.Header().Set("HX-Redirect", "/admin/logs")
	w.WriteHeader(http.StatusOK)
}

func Register(w http.ResponseWriter, r *http.Request) {
	// Check if registration is allowed (first-user setup only)
	if !IsRegistrationAllowed() {
		slog.Warn("registration blocked: admin user already exists", "source", "auth")
		http.Error(w, "Registration is disabled", http.StatusForbidden)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Validate email format
	if !ValidateEmail(email) {
		slog.Warn("registration failed: invalid email format", "source", "auth", "email", email)
		templates.RegisterForm("Invalid email format", email).Render(r.Context(), w)
		return
	}

	if err := ValidatePassword(password); err != nil {
		slog.Warn("registration failed: weak password", "source", "auth", "email", email, "reason", err.Error())
		templates.RegisterForm(err.Error(), email).Render(r.Context(), w)
		return
	}

	var existing models.User
	if err := database.DB.Where("email = ?", email).First(&existing).Error; err == nil {
		slog.Warn("registration failed: email exists", "source", "auth", "email", email)
		templates.RegisterForm("Email already registered", email).Render(r.Context(), w)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("registration failed: hash error", "source", "auth", "error", err.Error())
		templates.RegisterForm("Something went wrong", email).Render(r.Context(), w)
		return
	}

	user := models.User{Email: email, Password: string(hashed)}
	if err := database.DB.Create(&user).Error; err != nil {
		slog.Error("registration failed: db error", "source", "auth", "error", err.Error())
		templates.RegisterForm("Failed to create account", email).Render(r.Context(), w)
		return
	}

	slog.Info("user registered", "source", "auth", "user_id", user.ID, "email", email)

	session, _ := Store.Get(r, "session")
	session.Values["user_id"] = user.ID
	session.Values["email"] = user.Email
	session.Values["auth_method"] = "local"
	session.Save(r, w)

	w.Header().Set("HX-Redirect", "/admin/logs")
	w.WriteHeader(http.StatusOK)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session")
	userID, _ := session.Values["user_id"].(uint)
	slog.Info("user logged out", "source", "auth", "user_id", userID)

	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1
	session.Save(r, w)

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// GetCurrentUser is a variable to allow mocking in tests
var GetCurrentUser = func(r *http.Request) *models.User {
	session, err := Store.Get(r, "session")
	if err != nil {
		return nil
	}
	userID, ok := session.Values["user_id"].(uint)
	if !ok {
		return nil
	}
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return nil
	}
	return &user
}


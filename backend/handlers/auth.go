package handlers

import (
	"log/slog"
	"net/http"
	"todo-app/backend/config"
	"todo-app/backend/database"
	"todo-app/backend/models"
	"todo-app/frontend/templates"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var Store = sessions.NewCookieStore([]byte("super-secret-key-change-in-prod"))

// InitSession configures the session store with timeout from config
func InitSession() {
	Store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(config.C.Session.Timeout.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	templates.Login("", "").Render(r.Context(), w)
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
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
	email := r.FormValue("email")
	password := r.FormValue("password")

	if len(password) < 6 {
		slog.Warn("registration failed: password too short", "source", "auth", "email", email)
		templates.RegisterForm("Password must be at least 6 characters", email).Render(r.Context(), w)
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


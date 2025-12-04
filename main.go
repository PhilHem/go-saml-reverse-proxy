package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"
	"todo-app/backend/config"
	"todo-app/backend/database"
	"todo-app/backend/handlers"
	"todo-app/backend/logger"
	"todo-app/backend/middleware"
)

func main() {
	// Load configuration
	if err := config.Load(); err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize session store with configured timeout
	handlers.InitSession()

	if err := database.Init(); err != nil {
		log.Fatal("Failed to init database:", err)
	}

	// Initialize structured logging
	slog.SetDefault(slog.New(logger.NewDBHandler(database.DB)))
	go logger.CleanupOldLogs(database.DB, 48*time.Hour) // Keep logs for 2 days

	// Initialize SAML
	if err := handlers.InitSAML(); err != nil {
		log.Fatal("Failed to init SAML:", err)
	}

	// Initialize Proxy
	if err := handlers.InitProxy(); err != nil {
		log.Fatal("Failed to init proxy:", err)
	}

	slog.Info("server starting", "source", "main", "listen", config.C.Listen, "public_url", config.C.PublicURL)

	mux := http.NewServeMux()

	// Health check (unauthenticated, for load balancers)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// SAML routes
	mux.HandleFunc("GET /saml/metadata", handlers.SAMLMetadata)
	mux.HandleFunc("POST /saml/acs", handlers.SAMLACS)
	mux.HandleFunc("GET /saml/login", handlers.SAMLLogin)
	mux.HandleFunc("GET /saml/logout", handlers.SAMLLogout)

	// Admin auth routes (public)
	mux.HandleFunc("GET /admin/login", handlers.LoginPage)
	mux.HandleFunc("POST /admin/login", handlers.Login)
	mux.HandleFunc("GET /admin/register", handlers.RegisterPage)
	mux.HandleFunc("POST /admin/register", handlers.Register)
	mux.HandleFunc("POST /admin/logout", handlers.Logout)

	// Admin root redirects to logs
	mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/logs", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/logs", http.StatusSeeOther)
	})

	// Admin logs routes (require local username/password auth)
	mux.HandleFunc("GET /admin/logs", middleware.RequireLocalAuth(handlers.LogsPage))
	mux.HandleFunc("GET /admin/api/logs", middleware.RequireLocalAuth(handlers.GetLogs))
	mux.HandleFunc("GET /admin/api/logs/sources", middleware.RequireLocalAuth(handlers.GetLogSources))
	mux.HandleFunc("GET /admin/api/logs/timeline", middleware.RequireLocalAuth(handlers.GetLogTimeline))
	mux.HandleFunc("DELETE /admin/api/logs", middleware.RequireLocalAuth(handlers.DeleteLogs))

	// Reverse proxy - all other routes forward to upstream (require SAML auth)
	mux.HandleFunc("/", middleware.RequireProxyAuth(handlers.Proxy))

	fmt.Printf("Server running at %s (public: %s)\n", config.C.Listen, config.C.PublicURL)
	log.Fatal(http.ListenAndServe(config.C.Listen, mux))
}

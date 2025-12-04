package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/handlers"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/logger"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/middleware"
)

// Rate limiter for auth endpoints (10 requests per minute)
var authRateLimiter = middleware.NewRateLimiter(10, time.Minute)

func main() {
	// Load configuration
	if err := config.Load(); err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Initialize session store with configured secret and timeout
	if err := handlers.InitSession(); err != nil {
		log.Fatal("Failed to init session:", err)
	}

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

	// Admin auth routes (public, rate limited)
	mux.HandleFunc("GET /admin/login", handlers.LoginPage)
	mux.HandleFunc("POST /admin/login", authRateLimiter.LimitFunc(handlers.Login))
	mux.HandleFunc("GET /admin/register", handlers.RegisterPage)
	mux.HandleFunc("POST /admin/register", authRateLimiter.LimitFunc(handlers.Register))
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
	mux.HandleFunc("GET /admin/api/db/stats", middleware.RequireLocalAuth(handlers.GetDBStats))
	mux.HandleFunc("DELETE /admin/api/logs", middleware.RequireLocalAuth(handlers.DeleteLogs))

	// Reverse proxy - all other routes forward to upstream (require SAML auth)
	mux.HandleFunc("/", middleware.RequireProxyAuth(handlers.Proxy))

	// Wrap all routes with security headers
	handler := middleware.SecurityHeaders(mux)

	fmt.Printf("Server running at %s (public: %s)\n", config.C.Listen, config.C.PublicURL)
	if config.C.TLS.Enabled {
		slog.Info("starting server with TLS", "source", "main")
		log.Fatal(http.ListenAndServeTLS(config.C.Listen, config.C.TLS.Cert, config.C.TLS.Key, handler))
	} else {
		log.Fatal(http.ListenAndServe(config.C.Listen, handler))
	}
}

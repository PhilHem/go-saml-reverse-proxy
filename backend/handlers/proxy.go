package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
)

var upstreamURL *url.URL

func InitProxy() error {
	var err error
	upstreamURL, err = url.Parse(config.C.Upstream)
	if err != nil {
		slog.Error("proxy init failed: invalid upstream URL", "source", "proxy", "error", err.Error())
		return err
	}

	slog.Info("proxy initialized", "source", "proxy", "upstream", config.C.Upstream)
	return nil
}

// Proxy forwards authenticated requests to the upstream server
func Proxy(w http.ResponseWriter, r *http.Request) {
	user := GetCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = upstreamURL.Scheme
			req.URL.Host = upstreamURL.Host
			req.Host = upstreamURL.Host

			// Path is forwarded as-is (no prefix stripping)

			// Strip potentially spoofed headers from incoming request
			req.Header.Del("X-Forwarded-User")
			req.Header.Del("X-Forwarded-Email")
			req.Header.Del("X-Forwarded-Groups")

			// Inject authenticated user info
			req.Header.Set("X-Forwarded-User", user.Email)
			req.Header.Set("X-Forwarded-Email", user.Email)

			slog.Info("proxying request",
				"source", "proxy",
				"method", req.Method,
				"path", req.URL.Path,
				"user", user.Email,
				"upstream", upstreamURL.Host,
			)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("proxy error", "source", "proxy", "error", err.Error())
			http.Error(w, "Upstream unavailable", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// RED: Test that rate limiter blocks excessive requests
func TestRateLimiter_BlocksExcessiveRequests(t *testing.T) {
	// Create rate limiter: 5 requests per second
	limiter := NewRateLimiter(5, time.Second)

	handler := limiter.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 10 requests quickly from same IP
	blocked := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			blocked++
		}
	}

	// At least some should be blocked (more than 5)
	if blocked == 0 {
		t.Error("Rate limiter should block some requests when limit exceeded")
	}
}

// RED: Test that rate limiter allows requests under limit
func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	// Create rate limiter: 10 requests per second
	limiter := NewRateLimiter(10, time.Second)

	handler := limiter.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 5 requests (under limit)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should be allowed, got %d", i, rec.Code)
		}
	}
}

// RED: Test that different IPs have separate limits
func TestRateLimiter_SeparateLimitsPerIP(t *testing.T) {
	limiter := NewRateLimiter(2, time.Second)

	handler := limiter.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 2 requests from IP1 (should all pass)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("IP1 request %d should be allowed", i)
		}
	}

	// Make 2 requests from IP2 (should also pass - separate limit)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("IP2 request %d should be allowed", i)
		}
	}
}




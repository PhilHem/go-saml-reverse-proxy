package config

import (
	"os"
	"testing"
	"time"
)

// RED: Test that session timeout can be configured
func TestConfig_SessionTimeout(t *testing.T) {
	// Reset config
	C = Config{}

	// Set env var for session timeout
	os.Setenv("SESSION_TIMEOUT", "1h")
	defer os.Unsetenv("SESSION_TIMEOUT")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	expected := 1 * time.Hour
	if C.Session.Timeout != expected {
		t.Errorf("Expected session timeout %v, got %v", expected, C.Session.Timeout)
	}
}

// RED: Test session timeout default value
func TestConfig_SessionTimeoutDefault(t *testing.T) {
	// Reset config
	C = Config{}

	// Clear any env var
	os.Unsetenv("SESSION_TIMEOUT")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	// Default should be 24 hours
	expected := 24 * time.Hour
	if C.Session.Timeout != expected {
		t.Errorf("Expected default session timeout %v, got %v", expected, C.Session.Timeout)
	}
}


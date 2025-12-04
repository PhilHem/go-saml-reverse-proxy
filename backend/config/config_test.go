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

// Test TLS config from environment
func TestConfig_TLSFromEnv(t *testing.T) {
	C = Config{}

	os.Setenv("TLS_ENABLED", "true")
	os.Setenv("TLS_CERT", "/path/to/cert.pem")
	os.Setenv("TLS_KEY", "/path/to/key.pem")
	defer func() {
		os.Unsetenv("TLS_ENABLED")
		os.Unsetenv("TLS_CERT")
		os.Unsetenv("TLS_KEY")
	}()

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if !C.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if C.TLS.Cert != "/path/to/cert.pem" {
		t.Errorf("Expected TLS cert path, got %s", C.TLS.Cert)
	}
	if C.TLS.Key != "/path/to/key.pem" {
		t.Errorf("Expected TLS key path, got %s", C.TLS.Key)
	}
}

// Test TLS disabled by default
func TestConfig_TLSDisabledByDefault(t *testing.T) {
	C = Config{}
	os.Unsetenv("TLS_ENABLED")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if C.TLS.Enabled {
		t.Error("TLS should be disabled by default")
	}
}

// RED: Test database path from environment
func TestConfig_DatabasePathFromEnv(t *testing.T) {
	C = Config{}

	os.Setenv("DATABASE_PATH", "/custom/path/app.db")
	defer os.Unsetenv("DATABASE_PATH")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if C.DatabasePath != "/custom/path/app.db" {
		t.Errorf("Expected database path /custom/path/app.db, got %s", C.DatabasePath)
	}
}

// RED: Test database path default
func TestConfig_DatabasePathDefault(t *testing.T) {
	C = Config{}
	os.Unsetenv("DATABASE_PATH")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if C.DatabasePath != "app.db" {
		t.Errorf("Expected default database path app.db, got %s", C.DatabasePath)
	}
}

// RED: Test IDP entity ID from environment
func TestConfig_IDPEntityIDFromEnv(t *testing.T) {
	C = Config{}

	os.Setenv("IDP_ENTITY_ID", "https://idp.uni-mannheim.de/idp/shibboleth")
	defer os.Unsetenv("IDP_ENTITY_ID")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if C.SAML.IDPEntityID != "https://idp.uni-mannheim.de/idp/shibboleth" {
		t.Errorf("Expected IDP entity ID, got %s", C.SAML.IDPEntityID)
	}
}

// RED: Test IDP entity ID default is empty
func TestConfig_IDPEntityIDDefault(t *testing.T) {
	C = Config{}
	os.Unsetenv("IDP_ENTITY_ID")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	if C.SAML.IDPEntityID != "" {
		t.Errorf("Expected empty IDP entity ID by default, got %s", C.SAML.IDPEntityID)
	}
}

// Test ParseSize with various formats
func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		hasError bool
	}{
		// Plain numbers (backward compatibility)
		{"1024", 1024, false},
		{"5368709120", 5368709120, false},

		// With suffixes
		{"1B", 1, false},
		{"1KB", 1024, false},
		{"1MB", 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"1TB", 1024 * 1024 * 1024 * 1024, false},

		// Case insensitive
		{"1kb", 1024, false},
		{"1Kb", 1024, false},
		{"5gb", 5 * 1024 * 1024 * 1024, false},

		// With decimals
		{"1.5GB", int64(1.5 * 1024 * 1024 * 1024), false},
		{"0.5MB", int64(0.5 * 1024 * 1024), false},

		// With spaces
		{" 1GB ", 1024 * 1024 * 1024, false},
		{"1 GB", 1024 * 1024 * 1024, false},

		// Error cases
		{"", 0, true},
		{"abc", 0, true},
		{"1XB", 0, true},
		{"-1GB", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseSize(tc.input)
			if tc.hasError {
				if err == nil {
					t.Errorf("Expected error for input %q, got none", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %q: %v", tc.input, err)
				}
				if result != tc.expected {
					t.Errorf("For input %q: expected %d, got %d", tc.input, tc.expected, result)
				}
			}
		})
	}
}

// Test LOGS_MAX_DB_SIZE env var with human-readable format
func TestConfig_LogsMaxDBSizeFromEnv(t *testing.T) {
	C = Config{}

	os.Setenv("LOGS_MAX_DB_SIZE", "10GB")
	defer os.Unsetenv("LOGS_MAX_DB_SIZE")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	expected := int64(10 * 1024 * 1024 * 1024)
	if C.Logs.MaxDBSize != expected {
		t.Errorf("Expected MaxDBSize %d, got %d", expected, C.Logs.MaxDBSize)
	}
}

// Test LOGS_MAX_DB_SIZE default value
func TestConfig_LogsMaxDBSizeDefault(t *testing.T) {
	C = Config{}
	os.Unsetenv("LOGS_MAX_DB_SIZE")

	if err := Load(); err != nil {
		t.Fatal(err)
	}

	expected := int64(5 * 1024 * 1024 * 1024) // 5GB default
	if C.Logs.MaxDBSize != expected {
		t.Errorf("Expected default MaxDBSize %d, got %d", expected, C.Logs.MaxDBSize)
	}
}


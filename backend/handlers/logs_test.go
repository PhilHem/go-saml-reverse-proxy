package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/config"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/database"
	"github.com/PhilHem/go-saml-reverse-proxy/backend/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) {
	var err error
	database.DB, err = gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	database.DB.AutoMigrate(&models.User{}, &models.LogEntry{})
}

// RED: Test timeline with various resolution values (ensures no SQL injection)
func TestGetLogTimeline_Resolutions(t *testing.T) {
	setupTestDB(t)
	config.C.Logs.MaxDBSize = 5 * 1024 * 1024 * 1024

	resolutions := []string{"1m", "5m", "15m", "1h", "1d", "auto", ""}

	for _, res := range resolutions {
		t.Run("resolution_"+res, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/api/logs/timeline?range=1h&resolution="+res, nil)
			rec := httptest.NewRecorder()

			GetLogTimeline(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("Expected 200 for resolution %s, got %d: %s", res, rec.Code, rec.Body.String())
			}

			// Should return valid JSON array
			var result []TimelinePoint
			if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
				t.Errorf("Invalid JSON response for resolution %s: %v", res, err)
			}
		})
	}
}

// RED: Test that malicious resolution values don't cause SQL errors
func TestGetLogTimeline_InvalidResolution(t *testing.T) {
	setupTestDB(t)

	// Test with potentially dangerous input
	dangerousInputs := []string{
		"'; DROP TABLE log_entries;--",
		"1m; DELETE FROM",
		"<script>alert(1)</script>",
	}

	for _, input := range dangerousInputs {
		t.Run("dangerous_input", func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/api/logs/timeline?range=1h&resolution="+url.QueryEscape(input), nil)
			rec := httptest.NewRecorder()

			GetLogTimeline(rec, req)

			// Should either return OK with default resolution or handle gracefully
			// Most importantly, should NOT cause database errors
			if rec.Code == http.StatusInternalServerError {
				t.Errorf("Server error for input %s: %s", input, rec.Body.String())
			}
		})
	}
}


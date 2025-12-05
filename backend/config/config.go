package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseSize converts a human-readable size string (e.g., "5GB", "500MB", "1024KB")
// to bytes. Supports B, KB, MB, GB, TB suffixes (case-insensitive).
// Also accepts plain numbers as bytes for backward compatibility.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Try parsing as plain number first (backward compatibility)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}

	// Parse with unit suffix
	re := regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: %s (use e.g., '5GB', '500MB', '1024KB')", s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in size: %s", s)
	}

	unit := strings.ToUpper(matches[2])
	if unit == "" {
		unit = "B"
	}

	multipliers := map[string]float64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	multiplier, ok := multipliers[unit]
	if !ok {
		return 0, fmt.Errorf("unknown size unit: %s", unit)
	}

	return int64(value * multiplier), nil
}

type Config struct {
	Listen             string        `yaml:"listen"`
	PublicURL          string        `yaml:"public_url"`
	DatabasePath       string        `yaml:"database_path"`
	SAML               SAMLConfig    `yaml:"saml"`
	Session            SessionConfig `yaml:"session"`
	Upstream           string        `yaml:"upstream"`
	UpstreamSkipVerify bool          `yaml:"upstream_skip_verify"` // Skip TLS certificate verification for upstream
	Logs               LogsConfig    `yaml:"logs"`
	TLS                TLSConfig     `yaml:"tls"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

type SAMLConfig struct {
	IDPMetadataURL    string   `yaml:"idp_metadata_url"`
	IDPEntityID       string   `yaml:"idp_entity_id"`       // Optional: select specific IDP from federation metadata
	SPCert            string   `yaml:"sp_cert"`
	SPKey             string   `yaml:"sp_key"`
	AllowIDPInitiated bool     `yaml:"allow_idp_initiated"` // Default false for security
	AllowedDomains    []string `yaml:"allowed_domains"`     // Email domains allowed for auto-provisioning
}

type SessionConfig struct {
	Timeout time.Duration `yaml:"timeout"`
	Secret  string        `yaml:"secret"`
}

type LogsConfig struct {
	MaxDBSize    int64  `yaml:"-"`           // Parsed size in bytes (not directly from YAML)
	MaxDBSizeRaw string `yaml:"max_db_size"` // Human-readable size (e.g., "5GB", "500MB")
}

var C Config

func Load() error {
	// Defaults
	C = Config{
		Listen:       ":8080",
		PublicURL:    "http://localhost:8080",
		DatabasePath: "app.db",
		Upstream:     "http://localhost:9000",
		SAML: SAMLConfig{
			IDPMetadataURL: "http://localhost:7000/metadata",
			SPCert:         "sp-cert.pem",
			SPKey:          "sp-key.pem",
		},
		Session: SessionConfig{
			Timeout: 24 * time.Hour,
		},
		Logs: LogsConfig{
			MaxDBSize: 5 * 1024 * 1024 * 1024, // 5GB
		},
	}

	// Load from YAML if exists
	if data, err := os.ReadFile("config.yaml"); err == nil {
		if err := yaml.Unmarshal(data, &C); err != nil {
			return err
		}
	}

	// Parse human-readable size for MaxDBSize
	if C.Logs.MaxDBSizeRaw != "" {
		if size, err := ParseSize(C.Logs.MaxDBSizeRaw); err == nil {
			C.Logs.MaxDBSize = size
		}
	}

	// Environment overrides
	if v := os.Getenv("LISTEN"); v != "" {
		C.Listen = v
	}
	if v := os.Getenv("PUBLIC_URL"); v != "" {
		C.PublicURL = v
	}
	if v := os.Getenv("UPSTREAM_URL"); v != "" {
		C.Upstream = v
	}
	if v := os.Getenv("IDP_METADATA_URL"); v != "" {
		C.SAML.IDPMetadataURL = v
	}
	if v := os.Getenv("IDP_ENTITY_ID"); v != "" {
		C.SAML.IDPEntityID = v
	}
	if v := os.Getenv("SP_CERT"); v != "" {
		C.SAML.SPCert = v
	}
	if v := os.Getenv("SP_KEY"); v != "" {
		C.SAML.SPKey = v
	}
	if v := os.Getenv("SESSION_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			C.Session.Timeout = d
		}
	}
	if v := os.Getenv("SESSION_SECRET"); v != "" {
		C.Session.Secret = v
	}
	if v := os.Getenv("LOGS_MAX_DB_SIZE"); v != "" {
		if size, err := ParseSize(v); err == nil {
			C.Logs.MaxDBSize = size
		}
	}
	if v := os.Getenv("TLS_ENABLED"); v == "true" {
		C.TLS.Enabled = true
	}
	if v := os.Getenv("TLS_CERT"); v != "" {
		C.TLS.Cert = v
	}
	if v := os.Getenv("TLS_KEY"); v != "" {
		C.TLS.Key = v
	}
	if v := os.Getenv("DATABASE_PATH"); v != "" {
		C.DatabasePath = v
	}
	if v := os.Getenv("UPSTREAM_SKIP_VERIFY"); v == "true" {
		C.UpstreamSkipVerify = true
	}

	return nil
}


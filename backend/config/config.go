package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string        `yaml:"listen"`
	PublicURL string        `yaml:"public_url"`
	SAML      SAMLConfig    `yaml:"saml"`
	Session   SessionConfig `yaml:"session"`
	Upstream  string        `yaml:"upstream"`
}

type SAMLConfig struct {
	IDPMetadataURL string `yaml:"idp_metadata_url"`
	SPCert         string `yaml:"sp_cert"`
	SPKey          string `yaml:"sp_key"`
}

type SessionConfig struct {
	Timeout time.Duration `yaml:"timeout"`
}

var C Config

func Load() error {
	// Defaults
	C = Config{
		Listen:    ":8080",
		PublicURL: "http://localhost:8080",
		Upstream:  "http://localhost:9000",
		SAML: SAMLConfig{
			IDPMetadataURL: "http://localhost:7000/metadata",
			SPCert:         "sp-cert.pem",
			SPKey:          "sp-key.pem",
		},
		Session: SessionConfig{
			Timeout: 24 * time.Hour,
		},
	}

	// Load from YAML if exists
	if data, err := os.ReadFile("config.yaml"); err == nil {
		if err := yaml.Unmarshal(data, &C); err != nil {
			return err
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

	return nil
}


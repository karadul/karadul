package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ServerConfig holds configuration for the Karadul coordination server.
type ServerConfig struct {
	// Addr is the listen address, e.g. ":8080" or "0.0.0.0:443".
	Addr string `json:"addr"`

	// TLS configures HTTPS.
	TLS TLSConfig `json:"tls,omitempty"`

	// ApprovalMode controls how new nodes join: "auto" or "manual".
	ApprovalMode string `json:"approval_mode,omitempty"`

	// Subnet is the CGNAT subnet to allocate IPs from (default 100.64.0.0/10).
	Subnet string `json:"subnet,omitempty"`

	// DataDir is where the server stores its state.
	DataDir string `json:"data_dir,omitempty"`

	// DERP configures the embedded DERP relay.
	DERP DERPServerConfig `json:"derp,omitempty"`

	// LogLevel controls verbosity.
	LogLevel string `json:"log_level,omitempty"`

	// LogFormat controls output format: text or json.
	LogFormat string `json:"log_format,omitempty"`

	// RateLimit is the max requests/second per IP (0 = disabled).
	RateLimit int `json:"rate_limit,omitempty"`

	// AllowedOrigins lists permitted WebSocket origins. Empty = same-origin only.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`

	// AdminSecret is a bearer token required for /api/v1/admin/* endpoints.
	// If empty, admin endpoints are unprotected (use only in trusted networks).
	AdminSecret string `json:"admin_secret,omitempty"`
}

// TLSConfig holds TLS certificate configuration.
type TLSConfig struct {
	// Enabled enables TLS.
	Enabled bool `json:"enabled,omitempty"`

	// CertFile is the path to the TLS certificate PEM file.
	CertFile string `json:"cert_file,omitempty"`

	// KeyFile is the path to the TLS private key PEM file.
	KeyFile string `json:"key_file,omitempty"`

	// SelfSigned generates a self-signed certificate on startup if no files provided.
	SelfSigned bool `json:"self_signed,omitempty"`
}

// DERPServerConfig configures the embedded DERP relay.
type DERPServerConfig struct {
	// Enabled enables the embedded DERP relay server.
	Enabled bool `json:"enabled,omitempty"`

	// Addr is the listen address for DERP (defaults to same as coordination).
	Addr string `json:"addr,omitempty"`
}

// DefaultServerConfig returns a ServerConfig with sane defaults.
func DefaultServerConfig() *ServerConfig {
	home, _ := os.UserHomeDir()
	return &ServerConfig{
		Addr:         ":8080",
		ApprovalMode: "auto",
		Subnet:       "100.64.0.0/10",
		DataDir:      filepath.Join(home, ".karadul", "server"),
		LogLevel:     "info",
		LogFormat:    "text",
		RateLimit:    100,
		DERP: DERPServerConfig{
			Enabled: true,
		},
	}
}

// LoadServerConfig reads a JSON config file and merges it over defaults.
// The file may be either:
//   - flat: {"addr": ":8080", "subnet": "100.64.0.0/10", ...}
//   - nested: {"server": {"addr": ":8080", ...}, "node": {...}}
//
// When nested, only the "server" key is used; the "node" key is ignored.
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config %s: %w", path, err)
	}

	// Try nested format first: {"server": {...}}
	var wrapper struct {
		Server json.RawMessage `json:"server"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Server) > 0 {
		if err := json.Unmarshal(wrapper.Server, cfg); err != nil {
			return nil, fmt.Errorf("parse server config %s: %w", path, err)
		}
		return cfg, nil
	}

	// Fall back to flat format.
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse server config %s: %w", path, err)
	}
	return cfg, nil
}

// SaveServerConfig writes the server config to path.
func SaveServerConfig(cfg *ServerConfig, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

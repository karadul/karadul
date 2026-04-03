package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// NodeConfig holds configuration for a Karadul mesh node.
type NodeConfig struct {
	// ServerURL is the coordination server endpoint.
	ServerURL string `json:"server_url"`

	// Hostname is this node's name in the mesh. Defaults to OS hostname.
	Hostname string `json:"hostname,omitempty"`

	// PrivateKeyFile is the path to the node's private key file.
	PrivateKeyFile string `json:"private_key_file,omitempty"`

	// AuthKey is a pre-authentication key issued by the coordination server.
	AuthKey string `json:"auth_key,omitempty"`

	// AdvertiseRoutes are the subnet CIDRs this node will advertise.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`

	// AcceptRoutes enables accepting subnet routes from other nodes.
	AcceptRoutes bool `json:"accept_routes,omitempty"`

	// ExitNode is the public key of the peer to use as exit node.
	ExitNode string `json:"exit_node,omitempty"`

	// AdvertiseExitNode makes this node available as an exit node.
	AdvertiseExitNode bool `json:"advertise_exit_node,omitempty"`

	// DNS holds DNS configuration.
	DNS DNSConfig `json:"dns,omitempty"`

	// LogLevel controls verbosity: debug, info, warn, error.
	LogLevel string `json:"log_level,omitempty"`

	// LogFormat controls output: text or json.
	LogFormat string `json:"log_format,omitempty"`

	// ListenPort is the UDP port for WireGuard-style packets. 0 = random.
	ListenPort int `json:"listen_port,omitempty"`

	// DataDir is where state files are stored.
	DataDir string `json:"data_dir,omitempty"`
}

// DNSConfig configures the node's DNS behaviour.
type DNSConfig struct {
	// Enabled enables the built-in DNS resolver.
	Enabled bool `json:"enabled,omitempty"`

	// OverrideSystem rewrites system DNS to point at the karadul resolver.
	OverrideSystem bool `json:"override_system,omitempty"`

	// Upstream is the upstream DNS server to forward non-mesh queries to.
	Upstream string `json:"upstream,omitempty"`
}

// DefaultNodeConfig returns a NodeConfig with sane defaults.
func DefaultNodeConfig() *NodeConfig {
	home, _ := os.UserHomeDir()
	return &NodeConfig{
		LogLevel:  "info",
		LogFormat: "text",
		DataDir:   filepath.Join(home, ".karadul"),
		DNS: DNSConfig{
			Enabled:  true,
			Upstream: "1.1.1.1:53",
		},
	}
}

// LoadNodeConfig reads a JSON config file and merges it over defaults.
// The file may be either:
//   - flat: {"server_url": "...", "hostname": "...", ...}
//   - nested: {"server": {...}, "node": {"server_url": "...", ...}}
//
// When nested, only the "node" key is used; the "server" key is ignored.
func LoadNodeConfig(path string) (*NodeConfig, error) {
	cfg := DefaultNodeConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	// Try nested format first: {"node": {...}}
	var wrapper struct {
		Node json.RawMessage `json:"node"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Node) > 0 {
		if err := json.Unmarshal(wrapper.Node, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		return cfg, nil
	}

	// Fall back to flat format.
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// SaveNodeConfig writes the config to path as JSON.
func SaveNodeConfig(cfg *NodeConfig, path string) error {
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

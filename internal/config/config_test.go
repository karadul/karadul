package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultNodeConfig(t *testing.T) {
	cfg := DefaultNodeConfig()
	if cfg.ListenPort != 0 {
		t.Fatalf("default listen port should be 0 (random), got %d", cfg.ListenPort)
	}
	if cfg.DataDir == "" {
		t.Fatal("data dir should not be empty")
	}
}

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.Addr == "" {
		t.Fatal("addr should not be empty")
	}
	if cfg.Subnet == "" {
		t.Fatal("subnet should not be empty")
	}
	if cfg.ApprovalMode != "auto" && cfg.ApprovalMode != "manual" {
		t.Fatalf("unknown approval mode: %q", cfg.ApprovalMode)
	}
}

func TestLoadNodeConfig_NotFound(t *testing.T) {
	_, err := LoadNodeConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadServerConfig_NotFound(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/path/server.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveLoadNodeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	cfg := DefaultNodeConfig()
	cfg.Hostname = "test-save-host"
	cfg.ServerURL = "https://coord.example.com"
	cfg.ListenPort = 51820

	if err := SaveNodeConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadNodeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Hostname != cfg.Hostname {
		t.Fatalf("hostname: %q != %q", loaded.Hostname, cfg.Hostname)
	}
	if loaded.ServerURL != cfg.ServerURL {
		t.Fatalf("server_url mismatch")
	}
	if loaded.ListenPort != cfg.ListenPort {
		t.Fatalf("listen_port: %d != %d", loaded.ListenPort, cfg.ListenPort)
	}
}

func TestNodeConfig_JSONRoundtrip(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.AdvertiseRoutes = []string{"192.168.1.0/24", "10.0.0.0/8"}
	cfg.AdvertiseExitNode = true

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var loaded NodeConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.AdvertiseRoutes) != 2 {
		t.Fatalf("routes: %v", loaded.AdvertiseRoutes)
	}
	if !loaded.AdvertiseExitNode {
		t.Fatal("exit node flag lost")
	}
}

func TestValidateServerConfig_Valid(t *testing.T) {
	cfg := DefaultServerConfig()
	if err := ValidateServerConfig(cfg); err != nil {
		t.Fatalf("default server config should be valid: %v", err)
	}
}

func TestValidateServerConfig_BadSubnet(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Subnet = "not-a-cidr"
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("bad subnet should fail validation")
	}
}

func TestValidateServerConfig_TLSRequiresCert(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.SelfSigned = false
	cfg.TLS.CertFile = ""
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("TLS without cert should fail validation")
	}
}

func TestValidateNodeConfig_BadLogLevel(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com" // required
	cfg.LogLevel = "verbosemax"                 // not a real level
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("invalid log level should fail")
	}
}

func TestValidateNodeConfig_ValidFull(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com"
	cfg.ListenPort = 51820
	cfg.AdvertiseRoutes = []string{"192.168.0.0/24"}
	if err := ValidateNodeConfig(cfg); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateNodeConfig_BadRoute(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com"
	cfg.AdvertiseRoutes = []string{"not-a-cidr"}
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("bad route should fail")
	}
}

func TestSaveLoadServerConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	cfg := DefaultServerConfig()
	cfg.Addr = ":9999"
	cfg.ApprovalMode = "manual"
	cfg.RateLimit = 50

	if err := SaveServerConfig(cfg, path); err != nil {
		t.Fatalf("SaveServerConfig: %v", err)
	}

	loaded, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if loaded.Addr != cfg.Addr {
		t.Errorf("Addr: got %q, want %q", loaded.Addr, cfg.Addr)
	}
	if loaded.ApprovalMode != cfg.ApprovalMode {
		t.Errorf("ApprovalMode: got %q, want %q", loaded.ApprovalMode, cfg.ApprovalMode)
	}
	if loaded.RateLimit != cfg.RateLimit {
		t.Errorf("RateLimit: got %d, want %d", loaded.RateLimit, cfg.RateLimit)
	}
}

func TestLoadServerConfig_NestedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write a nested-format config (like config.example.json).
	nested := `{
		"server": {
			"addr": ":9999",
			"approval_mode": "manual",
			"subnet": "10.0.0.0/8",
			"rate_limit": 50,
			"admin_secret": "s3cret"
		},
		"node": {
			"server_url": "https://example.com"
		}
	}`
	if err := os.WriteFile(path, []byte(nested), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig nested: %v", err)
	}
	if cfg.Addr != ":9999" {
		t.Errorf("Addr: got %q, want %q", cfg.Addr, ":9999")
	}
	if cfg.ApprovalMode != "manual" {
		t.Errorf("ApprovalMode: got %q, want %q", cfg.ApprovalMode, "manual")
	}
	if cfg.Subnet != "10.0.0.0/8" {
		t.Errorf("Subnet: got %q, want %q", cfg.Subnet, "10.0.0.0/8")
	}
	if cfg.RateLimit != 50 {
		t.Errorf("RateLimit: got %d, want %d", cfg.RateLimit, 50)
	}
	if cfg.AdminSecret != "s3cret" {
		t.Errorf("AdminSecret: got %q, want %q", cfg.AdminSecret, "s3cret")
	}
}

func TestLoadNodeConfig_NestedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	nested := `{
		"server": {
			"addr": ":8080"
		},
		"node": {
			"server_url": "https://my-server:8080",
			"hostname": "test-node",
			"listen_port": 51820,
			"log_level": "debug"
		}
	}`
	if err := os.WriteFile(path, []byte(nested), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadNodeConfig(path)
	if err != nil {
		t.Fatalf("LoadNodeConfig nested: %v", err)
	}
	if cfg.ServerURL != "https://my-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "https://my-server:8080")
	}
	if cfg.Hostname != "test-node" {
		t.Errorf("Hostname: got %q, want %q", cfg.Hostname, "test-node")
	}
	if cfg.ListenPort != 51820 {
		t.Errorf("ListenPort: got %d, want %d", cfg.ListenPort, 51820)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: got %q, want %q", cfg.LogLevel, "debug")
	}
}

// ─── ValidateNodeConfig additional error paths ───────────────────────────────

func TestValidateNodeConfig_EmptyServerURL(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = ""
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("empty server_url should fail")
	}
}

func TestValidateNodeConfig_BadServerURLPrefix(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "ftp://coord.example.com"
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("server_url without http(s):// prefix should fail")
	}
}

func TestValidateNodeConfig_BadListenPort(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com"
	cfg.ListenPort = 99999
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("listen_port > 65535 should fail")
	}
}

func TestValidateNodeConfig_NegativeListenPort(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com"
	cfg.ListenPort = -1
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("negative listen_port should fail")
	}
}

func TestValidateNodeConfig_BadDNSUpstream(t *testing.T) {
	cfg := DefaultNodeConfig()
	cfg.ServerURL = "https://coord.example.com"
	cfg.DNS.Upstream = "not-a-host-port"
	if err := ValidateNodeConfig(cfg); err == nil {
		t.Fatal("invalid dns.upstream should fail")
	}
}

// ─── ValidateServerConfig additional error paths ─────────────────────────────

func TestValidateServerConfig_EmptyAddr(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Addr = ""
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("empty addr should fail")
	}
}

func TestValidateServerConfig_BadAddr(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Addr = "not-a-host-port"
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("invalid addr should fail")
	}
}

func TestValidateServerConfig_BadApprovalMode(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.ApprovalMode = "unknown"
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("invalid approval_mode should fail")
	}
}

func TestValidateServerConfig_BadLogLevel(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.LogLevel = "trace"
	if err := ValidateServerConfig(cfg); err == nil {
		t.Fatal("invalid log_level should fail in server config")
	}
}

// ─── LoadNodeConfig error paths ───────────────────────────────────────────────

func TestLoadNodeConfig_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeConfig(path); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoadServerConfig_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{{{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestConfigFile_SavePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.json")

	cfg := DefaultNodeConfig()
	if err := SaveNodeConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Config files should be readable (not mode 0000).
	if info.Mode().Perm() == 0 {
		t.Fatal("config file has no permissions")
	}
}

// TestSaveNodeConfig_MkdirAllFails verifies SaveNodeConfig returns an error when
// the directory cannot be created (blocked by a file at the parent path).
func TestSaveNodeConfig_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	// Create a file where the directory should be.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultNodeConfig()
	path := filepath.Join(blocker, "node.json")
	if err := SaveNodeConfig(cfg, path); err == nil {
		t.Fatal("expected error when MkdirAll is blocked by a file")
	}
}

// TestSaveNodeConfig_OpenFileFails verifies SaveNodeConfig returns an error when
// the file cannot be opened for writing (blocked by a directory at the target path).
func TestSaveNodeConfig_OpenFileFails(t *testing.T) {
	dir := t.TempDir()
	// Create a directory where the file should be written.
	path := filepath.Join(dir, "node.json")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultNodeConfig()
	if err := SaveNodeConfig(cfg, path); err == nil {
		t.Fatal("expected error when OpenFile is blocked by a directory")
	}
}

// TestSaveServerConfig_MkdirAllFails verifies SaveServerConfig returns an error when
// the directory cannot be created (blocked by a file at the parent path).
func TestSaveServerConfig_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	// Create a file where the directory should be.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultServerConfig()
	path := filepath.Join(blocker, "server.json")
	if err := SaveServerConfig(cfg, path); err == nil {
		t.Fatal("expected error when MkdirAll is blocked by a file")
	}
}

// TestSaveServerConfig_OpenFileFails verifies SaveServerConfig returns an error when
// the file cannot be opened for writing (blocked by a directory at the target path).
func TestSaveServerConfig_OpenFileFails(t *testing.T) {
	dir := t.TempDir()
	// Create a directory where the file should be written.
	path := filepath.Join(dir, "server.json")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultServerConfig()
	if err := SaveServerConfig(cfg, path); err == nil {
		t.Fatal("expected error when OpenFile is blocked by a directory")
	}
}

package coordinator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/config"
	klog "github.com/karadul/karadul/internal/log"
)

// --- Storage helpers ---

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestStore_AddNode_UpdateExisting verifies that calling AddNode with a duplicate ID
// updates the existing entry (covering the update-existing branch).
func TestStore_AddNode_UpdateExisting(t *testing.T) {
	s := newTestStore(t)
	n := &Node{
		ID: "dup-node", PublicKey: "pk-dup", Hostname: "original",
		VirtualIP: "100.64.0.42", Status: NodeStatusActive,
		RegisteredAt: time.Now(), LastSeen: time.Now(),
	}
	if err := s.AddNode(n); err != nil {
		t.Fatal(err)
	}

	// Call AddNode again with the same ID but updated hostname.
	n2 := *n
	n2.Hostname = "updated"
	if err := s.AddNode(&n2); err != nil {
		t.Fatalf("AddNode update-existing: %v", err)
	}

	got, ok := s.GetNode("dup-node")
	if !ok {
		t.Fatal("node not found after update")
	}
	if got.Hostname != "updated" {
		t.Errorf("hostname: want %q, got %q", "updated", got.Hostname)
	}
	// Only one entry should exist (not a second one).
	if count := len(s.ListNodes()); count != 1 {
		t.Errorf("want 1 node, got %d", count)
	}
}

// TestStore_GetNode_Found verifies GetNode returns a copy when the node exists.
func TestStore_GetNode_Found(t *testing.T) {
	s := newTestStore(t)
	node := &Node{
		ID:        "test-node-1",
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "host1",
		VirtualIP: "100.64.0.5",
		Status:    NodeStatusActive,
	}
	if err := s.AddNode(node); err != nil {
		t.Fatal(err)
	}

	got, ok := s.GetNode("test-node-1")
	if !ok {
		t.Fatal("GetNode: expected to find node")
	}
	if got.ID != "test-node-1" {
		t.Errorf("GetNode: id mismatch: %s", got.ID)
	}
	if got.Hostname != "host1" {
		t.Errorf("GetNode: hostname mismatch: %s", got.Hostname)
	}
	// Verify it's a copy (not the same pointer).
	got.Hostname = "modified"
	orig, _ := s.GetNode("test-node-1")
	if orig.Hostname == "modified" {
		t.Error("GetNode should return a copy, not the original pointer")
	}
}

// TestStore_GetNode_NotFound verifies GetNode returns false when the node is absent.
func TestStore_GetNode_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, ok := s.GetNode("nonexistent"); ok {
		t.Fatal("GetNode: expected not-found for nonexistent ID")
	}
}

// TestStore_Version verifies Version() is callable and returns a non-negative int64.
func TestStore_Version(t *testing.T) {
	s := newTestStore(t)
	v := s.Version()
	if v < 0 {
		t.Fatalf("Version() should be non-negative, got %d", v)
	}
}

// --- Server tests ---

func newTestServerConfig(t *testing.T) *config.ServerConfig {
	t.Helper()
	return &config.ServerConfig{
		Addr:         "127.0.0.1:0", // OS-assigned port
		Subnet:       "100.64.0.0/10",
		DataDir:      t.TempDir(),
		ApprovalMode: "auto",
	}
}

// TestNewServer verifies that NewServer initialises successfully with a valid config.
func TestNewServer(t *testing.T) {
	cfg := newTestServerConfig(t)
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
}

// TestNewServer_BadSubnet verifies that an invalid subnet returns an error.
func TestNewServer_BadSubnet(t *testing.T) {
	cfg := newTestServerConfig(t)
	cfg.Subnet = "not-a-subnet"
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	if _, err := NewServer(cfg, log); err == nil {
		t.Fatal("expected error for invalid subnet")
	}
}

// TestServer_Store verifies that the Store() accessor returns the non-nil store.
func TestServer_Store(t *testing.T) {
	cfg := newTestServerConfig(t)
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Store() == nil {
		t.Fatal("Server.Store() should not be nil")
	}
}

// TestServer_Start_Stop verifies that the server starts and shuts down via context cancel.
func TestServer_Start_Stop(t *testing.T) {
	cfg := newTestServerConfig(t)
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, nil) }()

	// Give it a moment to start.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop after context cancel")
	}
}

// TestGenerateSelfSignedCert verifies that a self-signed certificate is produced.
func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate DER blocks in result")
	}
}

// TestServer_Start_SelfSignedTLS verifies that the server starts with TLS enabled (self-signed).
func TestServer_Start_SelfSignedTLS(t *testing.T) {
	cfg := newTestServerConfig(t)
	cfg.TLS = config.TLSConfig{Enabled: true, SelfSigned: true}
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, nil) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("TLS server returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS server did not stop after context cancel")
	}
}

// --- Middleware tests ---

// TestRateLimitMiddleware_Disabled verifies that rps<=0 returns the original handler.
func TestRateLimitMiddleware_Disabled(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h, _ := rateLimitMiddleware(inner, 0)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if !called {
		t.Fatal("inner handler should be called when rate limit is disabled")
	}
}

// TestRateLimitMiddleware_AllowsRequests verifies that requests within the limit are served.
func TestRateLimitMiddleware_AllowsRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h, _ := rateLimitMiddleware(inner, 100) // 100 rps — plenty

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}
}

// TestRateLimitMiddleware_Throttles verifies that excessive requests are rejected.
func TestRateLimitMiddleware_Throttles(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h, _ := rateLimitMiddleware(inner, 2) // only 2 tokens initially

	makeReq := func() int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.2:9999"
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		return rw.Code
	}

	// First two should pass (token bucket starts at rps=2 tokens).
	codes := []int{makeReq(), makeReq(), makeReq()}
	got429 := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("expected at least one 429 after exceeding rate limit")
	}
}

// TestLoggingMiddleware verifies the logging middleware passes the request and logs.
func TestLoggingMiddleware(t *testing.T) {
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	})
	h := loggingMiddleware(inner, log)

	req := httptest.NewRequest("GET", "/test", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if !called {
		t.Fatal("inner handler should have been called")
	}
	if rw.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rw.Code)
	}
}

// TestResponseWriter_WriteHeader verifies that WriteHeader captures the status code.
func TestResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rec, code: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.code != http.StatusNotFound {
		t.Errorf("code: want 404, got %d", rw.code)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("underlying recorder code: want 404, got %d", rec.Code)
	}
}

// TestServer_Start_DoesNotImmediatelyError verifies that Start doesn't return an error right away.
func TestServer_Start_DoesNotImmediatelyError(t *testing.T) {
	cfg := newTestServerConfig(t)
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx, nil) }()

	select {
	case err := <-errCh:
		t.Fatalf("server stopped unexpectedly: %v", err)
	case <-time.After(50 * time.Millisecond):
		// Still running — good.
	}
	cancel()
}

// TestTlsConfig_WithCertFiles verifies that tlsConfig() loads a cert/key from files,
// covering the tls.LoadX509KeyPair branch.
func TestTlsConfig_WithCertFiles(t *testing.T) {
	// Generate an ECDSA key pair.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "karadul-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := newTestServerConfig(t)
	cfg.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg, err := srv.tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig with cert files: %v", err)
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate in tls config")
	}
}

// TestNewStore_BadJSON verifies NewStore returns an error when the state file
// exists but contains invalid JSON (covers the non-IsNotExist error branch in NewStore).
func TestNewStore_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{{{invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path)
	if err == nil {
		t.Fatal("expected error from NewStore when state file has invalid JSON")
	}
}

// TestStore_MarkAuthKeyUsed_Found verifies MarkAuthKeyUsed succeeds for an
// existing key (covers the success branch that sets Used=true).
func TestStore_MarkAuthKeyUsed_Found(t *testing.T) {
	s := newTestStore(t)
	k := &AuthKey{ID: "test-key-id", Key: "secret", Ephemeral: true, CreatedAt: time.Now()}
	if err := s.AddAuthKey(k); err != nil {
		t.Fatalf("AddAuthKey: %v", err)
	}
	if err := s.MarkAuthKeyUsed(k.ID); err != nil {
		t.Fatalf("MarkAuthKeyUsed: %v", err)
	}
}

// TestStore_MarkAuthKeyUsed_NotFound verifies MarkAuthKeyUsed returns an error
// for an unknown key ID.
func TestStore_MarkAuthKeyUsed_NotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.MarkAuthKeyUsed("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown key ID")
	}
}

// TestNewServer_WithExistingNodes verifies NewServer correctly reserves IPs for
// nodes already persisted in the state file (covers the "Re-reserve IPs" loop,
// including the ip != nil → Reserve and ip == nil → skip branches).
func TestNewServer_WithExistingNodes(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")

	// Pre-populate the store with two nodes: one valid VIP, one invalid VIP.
	s, err := NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.AddNode(&Node{
		ID:           "node-valid",
		PublicKey:    "pk-valid",
		Hostname:     "host1",
		VirtualIP:    "100.64.0.5",
		Status:       NodeStatusActive,
		RegisteredAt: now,
		LastSeen:     now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddNode(&Node{
		ID:           "node-bad-ip",
		PublicKey:    "pk-bad",
		Hostname:     "host2",
		VirtualIP:    "not-a-valid-ip", // will be skipped (ip == nil)
		Status:       NodeStatusActive,
		RegisteredAt: now,
		LastSeen:     now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ServerConfig{
		Addr:         "127.0.0.1:0",
		Subnet:       "100.64.0.0/10",
		DataDir:      dir,
		ApprovalMode: "auto",
	}
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatalf("NewServer with existing nodes: %v", err)
	}
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

// TestStore_Save_OpenFileFails verifies Save returns an error when the .tmp
// file path is blocked by a directory (covers the os.OpenFile error branch).
func TestStore_Save_OpenFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Block the .tmp path by creating a directory there.
	tmpPath := path + ".tmp"
	if err := os.MkdirAll(tmpPath, 0700); err != nil {
		t.Fatal(err)
	}

	if err := s.Save(); err == nil {
		t.Fatal("expected error when .tmp path is a directory")
	}
}

// TestServer_Start_ListenError verifies that Start returns an error
// when given an invalid address to listen on.
func TestServer_Start_ListenError(t *testing.T) {
	cfg := newTestServerConfig(t)
	cfg.Addr = "invalid-address:999999" // Invalid port
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = srv.Start(ctx, nil)
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

// TestServer_TlsConfig_InvalidCertFile verifies that tlsConfig returns an error
// when the cert file does not exist.
func TestServer_TlsConfig_InvalidCertFile(t *testing.T) {
	cfg := newTestServerConfig(t)
	cfg.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: "/nonexistent/path/cert.pem",
		KeyFile:  "/nonexistent/path/key.pem",
	}
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	_, err = srv.tlsConfig()
	if err == nil {
		t.Fatal("expected error for non-existent cert file")
	}
}

// TestServer_TlsConfig_InvalidKeyFile verifies that tlsConfig returns an error
// when the cert file exists but the key file does not.
func TestServer_TlsConfig_InvalidKeyFile(t *testing.T) {
	// Generate a temp cert file
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "nonexistent-key.pem")

	// Write a dummy cert file
	if err := os.WriteFile(certFile, []byte("dummy cert"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := newTestServerConfig(t)
	cfg.TLS = config.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	srv, err := NewServer(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	_, err = srv.tlsConfig()
	if err == nil {
		t.Fatal("expected error for non-existent key file")
	}
}

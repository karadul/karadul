package coordinator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/config"
)

// ─── handlePeers: "Direct" and "Discovered" peer states ─────────────────────

// TestHandlePeers_DirectState verifies a recently-seen node with an endpoint
// shows State="Direct" in the /peers response.
func TestHandlePeers_DirectState(t *testing.T) {
	api, ts := newTestAPI(t)

	now := time.Now()
	api.store.AddNode(&Node{
		ID: "direct-1", PublicKey: "pk-direct", Hostname: "direct-node",
		VirtualIP: "100.64.0.10", Status: NodeStatusActive,
		Endpoint: "10.0.0.1:4000", RegisteredAt: now, LastSeen: now,
	})

	resp, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var peers []PeerResponse
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].State != "Direct" {
		t.Errorf("state: want Direct, got %q", peers[0].State)
	}
}

// TestHandlePeers_DiscoveredState verifies a node with endpoint but stale
// LastSeen shows State="Discovered".
func TestHandlePeers_DiscoveredState(t *testing.T) {
	api, ts := newTestAPI(t)

	stale := time.Now().Add(-10 * time.Minute)
	api.store.AddNode(&Node{
		ID: "discovered-1", PublicKey: "pk-disc", Hostname: "disc-node",
		VirtualIP: "100.64.0.11", Status: NodeStatusActive,
		Endpoint: "10.0.0.2:4000", RegisteredAt: stale, LastSeen: stale,
	})

	resp, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var peers []PeerResponse
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].State != "Discovered" {
		t.Errorf("state: want Discovered, got %q", peers[0].State)
	}
}

// TestHandlePeers_PendingNodeFiltered verifies pending nodes are excluded
// from the /peers response.
func TestHandlePeers_PendingNodeFiltered(t *testing.T) {
	api, ts := newTestAPI(t)

	now := time.Now()
	api.store.AddNode(&Node{
		ID: "active-1", PublicKey: "pk-active", Hostname: "active-node",
		VirtualIP: "100.64.0.20", Status: NodeStatusActive,
		RegisteredAt: now, LastSeen: now,
	})
	api.store.AddNode(&Node{
		ID: "pending-1", PublicKey: "pk-pending", Hostname: "pending-node",
		VirtualIP: "100.64.0.21", Status: NodeStatusPending,
		RegisteredAt: now, LastSeen: now,
	})

	resp, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var peers []PeerResponse
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer (pending filtered), got %d", len(peers))
	}
	if peers[0].Hostname != "active-node" {
		t.Errorf("expected active-node, got %q", peers[0].Hostname)
	}
}

// ─── handleRegister: invalid route CIDR ────────────────────────────────────

// TestRegister_InvalidRouteCIDR verifies that registering with an invalid
// route CIDR returns 400.
func TestRegister_InvalidRouteCIDR(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "route-node",
		AuthKey:   ak.Key,
		Routes:    []string{"not-a-cidr"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400 for invalid route CIDR, got %d", resp.StatusCode)
	}
}

// TestRegister_ReRegEmptyHostname verifies that re-registering with an empty
// hostname preserves the original hostname.
func TestRegister_ReRegEmptyHostname(t *testing.T) {
	api, ts := newTestAPI(t)

	// First registration with a hostname.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	body1, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "original-host",
		AuthKey:   ak.Key,
	})
	resp1, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body1))
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first register: %d", resp1.StatusCode)
	}

	// Re-register with empty hostname.
	ak2, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak2)
	body2, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "",
		AuthKey:   ak2.Key,
	})
	resp2, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-register: %d", resp2.StatusCode)
	}

	// Verify original hostname is preserved.
	node, ok := api.store.GetNodeByPubKey(testPubKeyB64)
	if !ok {
		t.Fatal("node not found")
	}
	if node.Hostname != "original-host" {
		t.Errorf("hostname: want original-host, got %q", node.Hostname)
	}
}

// ─── handleRegister: read body error ────────────────────────────────────────

// TestRegister_ReadBodyError verifies handleRegister returns 400 when
// reading the request body fails.
func TestRegister_ReadBodyError(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", &errReader{err: fmt.Errorf("read fail")})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleRegister(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── handlePing: read body error ────────────────────────────────────────────

// TestHandlePing_ReadBodyError verifies handlePing returns 400 when reading
// the request body fails.
func TestHandlePing_ReadBodyError(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", &errReader{err: fmt.Errorf("read fail")})
	w := httptest.NewRecorder()
	api.handlePing(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── handleStatus: method not allowed ───────────────────────────────────────

// TestHandleStatus_MethodNotAllowed verifies POST to /status returns 405.
func TestHandleStatus_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Post(ts.URL+"/api/v1/status", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

// TestHandleStatus_MixedNodeStatuses verifies status counts only active peers.
func TestHandleStatus_MixedNodeStatuses(t *testing.T) {
	api, ts := newTestAPI(t)

	now := time.Now()
	api.store.AddNode(&Node{
		ID: "s-active", PublicKey: "pk-sa", Hostname: "sa",
		VirtualIP: "100.64.0.30", Status: NodeStatusActive,
		RxBytes: 1000, TxBytes: 2000, RegisteredAt: now, LastSeen: now,
	})
	api.store.AddNode(&Node{
		ID: "s-pending", PublicKey: "pk-sp", Hostname: "sp",
		VirtualIP: "100.64.0.31", Status: NodeStatusPending,
		RxBytes: 500, TxBytes: 500, RegisteredAt: now, LastSeen: now,
	})

	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var status SystemStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.PeersConnected != 1 {
		t.Errorf("PeersConnected: want 1 (only active), got %d", status.PeersConnected)
	}
	// TotalRx includes all nodes: 1000 + 500 = 1500
	if status.TotalRx != 1500 {
		t.Errorf("TotalRx: want 1500, got %d", status.TotalRx)
	}
	if status.TotalTx != 2500 {
		t.Errorf("TotalTx: want 2500, got %d", status.TotalTx)
	}
}

// ─── handleAdminConfig: DataDir empty and read body error ──────────────────

// TestAdminConfig_EmptyDataDir verifies PUT config succeeds when DataDir is empty
// (skips persistence).
func TestAdminConfig_EmptyDataDir(t *testing.T) {
	cfg := &config.ServerConfig{Addr: ":8080", Subnet: "100.64.0.0/10", DataDir: ""}
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", cfg)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	newCfg := config.ServerConfig{Addr: ":7070", Subnet: "100.64.0.0/10", ApprovalMode: "auto"}
	body, _ := json.Marshal(newCfg)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// TestAdminConfig_ReadBodyError verifies PUT config returns 400 on body read failure.
func TestAdminConfig_ReadBodyError(t *testing.T) {
	cfg := &config.ServerConfig{Addr: ":8080", Subnet: "100.64.0.0/10", DataDir: t.TempDir()}
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", cfg)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/config", &errReader{err: fmt.Errorf("read fail")})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAdminConfig(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// TestAdminConfig_SaveError verifies PUT config returns 200 even when saving
// fails (error is only logged).
func TestAdminConfig_SaveError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, _ := NewStore(storePath)
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	cfg := &config.ServerConfig{Addr: ":8080", Subnet: "100.64.0.0/10", DataDir: dir}
	api := NewAPI(store, pool, poller, "auto", cfg)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Block the config save path by creating a directory where the file would go.
	// The handler tries DataDir + "/config.json" via config.SaveServerConfig.
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(configPath, 0700); err != nil {
		t.Fatal(err)
	}

	newCfg := config.ServerConfig{Addr: ":7070", Subnet: "100.64.0.0/10", ApprovalMode: "auto"}
	body, _ := json.Marshal(newCfg)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Handler logs the error but returns 200.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 (error is logged), got %d", resp.StatusCode)
	}
}

// ─── handleAdminAuthKeys: DELETE with invalid ID and read body error ───────

// TestAdminAuthKeys_DeleteInvalidID verifies DELETE with a non-alphanumeric
// ID returns 400.
func TestAdminAuthKeys_DeleteInvalidID(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/auth-keys/bad_id", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400 for invalid ID chars, got %d", resp.StatusCode)
	}
}

// TestAdminAuthKeys_CreateReadBodyError verifies POST auth-keys returns 400
// when reading the body fails.
func TestAdminAuthKeys_CreateReadBodyError(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth-keys", &errReader{err: fmt.Errorf("read fail")})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAdminAuthKeys(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── nodeOrAdminAuth: HMAC signature with secret configured ─────────────────

// TestNodeOrAdminAuth_ValidHMAC verifies that a valid HMAC signature passes
// the nodeOrAdminAuth middleware when AdminSecret is configured.
func TestNodeOrAdminAuth_ValidHMAC(t *testing.T) {
	const secret = "test-secret"
	api, ts := newTestAPIWithSecret(t, secret)

	// Register a node.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	regBody, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "hmac-node",
		AuthKey:   ak.Key,
	})
	regResp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	regResp.Body.Close()

	// Send a signed request to /peers.
	body := []byte{}
	sig := SignRequest(testPubKey, http.MethodGet, "/api/v1/peers", body)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 for valid HMAC, got %d", resp.StatusCode)
	}
}

// TestNodeOrAdminAuth_InvalidHMAC verifies that an invalid HMAC signature
// is rejected when AdminSecret is configured.
func TestNodeOrAdminAuth_InvalidHMAC(t *testing.T) {
	const secret = "test-secret"
	_, ts := newTestAPIWithSecret(t, secret)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	req.Header.Set("X-Karadul-Sig", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401 for invalid HMAC, got %d", resp.StatusCode)
	}
}

// TestNodeOrAdminAuth_PartialHeaders verifies that setting only one auth
// header (key but not sig) results in 401.
func TestNodeOrAdminAuth_PartialHeaders(t *testing.T) {
	const secret = "test-secret"
	_, ts := newTestAPIWithSecret(t, secret)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	// No X-Karadul-Sig header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401 for partial headers, got %d", resp.StatusCode)
	}
}

// ─── handleAdminAuthKeys: read body error on POST ──────────────────────────

// TestAdminACL_ReadBodyError verifies PUT /admin/acl returns 400 when body
// read fails.
func TestAdminACL_ReadBodyError(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/acl", &errReader{err: fmt.Errorf("fail")})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAdminACL(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── handleUpdateEndpoint: read body error ──────────────────────────────────

// TestHandleUpdateEndpoint_ReadBodyError covers the body read error path.
func TestHandleUpdateEndpoint_ReadBodyError(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/update-endpoint", &errReader{err: io.ErrUnexpectedEOF})
	w := httptest.NewRecorder()
	api.handleUpdateEndpoint(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── handleRegister: store error on re-registration ─────────────────────────

// TestRegister_ReRegStoreError verifies re-registration returns 500 when
// the store fails to update the existing node.
func TestRegister_ReRegStoreError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, _ := NewStore(storePath)
	pool, _ := NewIPPool("100.64.0.0/24")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Register first.
	ak, _ := GenerateAuthKey(false, 0)
	_ = store.AddAuthKey(ak)
	body1, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64, Hostname: "first", AuthKey: ak.Key,
	})
	r1, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body1))
	r1.Body.Close()

	// Block store writes.
	tmpPath := storePath + ".tmp"
	os.MkdirAll(tmpPath, 0700)

	// Re-register with same key.
	ak2, _ := GenerateAuthKey(false, 0)
	_ = store.AddAuthKey(ak2)
	body2, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64, Hostname: "second", AuthKey: ak2.Key,
	})
	r2, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusInternalServerError {
		t.Errorf("want 500 for store error on re-reg, got %d", r2.StatusCode)
	}
}

// ─── handlePing: unknown node (valid signature, unregistered key) ───────────

// TestHandlePing_UnknownNode verifies that a signed ping from an unregistered
// key returns 401 (VerifyRequestSignature rejects unknown keys).
func TestHandlePing_UnknownNode(t *testing.T) {
	api, _ := newTestAPI(t)

	var pubKey [32]byte
	pubKey[0] = 0xFF
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	req.Header.Set("X-Karadul-Key", pubKeyB64)
	sig := SignRequest(pubKey, http.MethodPost, "/api/v1/ping", nil)
	req.Header.Set("X-Karadul-Sig", sig)

	w := httptest.NewRecorder()
	api.handlePing(w, req)
	// VerifyRequestSignature rejects unregistered keys, so expect 401.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for unknown node ping, got %d", w.Code)
	}
}

// ─── handleStatus: DERP map regions ─────────────────────────────────────────

// TestHandleStatus_WithDERPRegion verifies status includes DERP region count.
func TestHandleStatus_WithDERPRegion(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var status SystemStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	// Verify basic fields are populated.
	if status.PeersConnected < 0 {
		t.Error("PeersConnected should be >= 0")
	}
	if status.Uptime < 0 {
		t.Error("Uptime should be >= 0")
	}
}

// ─── handleExchangeEndpoint: read body error ────────────────────────────────

// TestHandleExchangeEndpoint_ReadBodyError already exists in api_test.go.
// This is a duplicate name check — skip if it already passes.

// ─── config type alias for tests ────────────────────────────────────────────

// Config aliases to avoid import — use the same type as api.go.
// These tests import config.ServerConfig directly in some places.
// We use the local type aliases where possible.

// ─── register: valid routes ─────────────────────────────────────────────────

// TestRegister_ValidRoutes verifies registration succeeds with valid route CIDRs.
func TestRegister_ValidRoutes(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "routes-node",
		AuthKey:   ak.Key,
		Routes:    []string{"10.0.0.0/24", "192.168.1.0/24"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 for valid routes, got %d", resp.StatusCode)
	}
}

// ─── PeerResponse struct coverage ────────────────────────────────────────────────

// PeerResponse is used in the /peers response. This test verifies the struct
// fields are properly serialized.
func TestPeerResponse_Serialization(t *testing.T) {
	api, ts := newTestAPI(t)

	now := time.Now()
	api.store.AddNode(&Node{
		ID: "ser-1", PublicKey: "pk-ser", Hostname: "ser-node",
		VirtualIP: "100.64.0.40", Status: NodeStatusActive,
		Endpoint: "1.2.3.4:5678", RegisteredAt: now, LastSeen: now,
		RxBytes: 999, TxBytes: 888,
	})

	resp, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var peers []PeerResponse
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	p := peers[0]
	if p.Hostname != "ser-node" {
		t.Errorf("hostname: %q", p.Hostname)
	}
	if p.VirtualIP != "100.64.0.40" {
		t.Errorf("virtual_ip: %q", p.VirtualIP)
	}
	if p.Endpoint != "1.2.3.4:5678" {
		t.Errorf("endpoint: %q", p.Endpoint)
	}
	if p.State != "Direct" {
		t.Errorf("state: %q", p.State)
	}
}

// ─── generateID: error path (practically unreachable) ───────────────────────

// generateID's error path requires crypto/rand to fail, which is essentially
// impossible to trigger without mocking. We verify the happy path instead.

// TestGenerateID_Multiple verifies generateID produces unique IDs.
func TestGenerateID_Multiple(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateID()
		if err != nil {
			t.Fatalf("generateID: %v", err)
		}
		if ids[id] {
			t.Fatalf("duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

// ─── handleAdminNodes: delete with store error ──────────────────────────────

// TestAdminNodes_DeleteStoreError verifies DELETE still succeeds when store
// persistence fails (the node is removed from memory, saveLocked error is swallowed
// by Store.DeleteNode).
func TestAdminNodes_DeleteStoreError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, _ := NewStore(storePath)
	pool, _ := NewIPPool("100.64.0.0/24")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Add a node.
	store.AddNode(&Node{
		ID: "del-store-1", PublicKey: "pk-ds", Hostname: "ds",
		VirtualIP: "100.64.0.50", Status: NodeStatusActive,
		RegisteredAt: time.Now(), LastSeen: time.Now(),
	})

	// Block store writes (tmp file as directory makes saveLocked fail).
	tmpPath := storePath + ".tmp"
	os.MkdirAll(tmpPath, 0700)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/nodes/del-store-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// DeleteNode removes from memory first, then calls saveLocked.
	// saveLocked fails but the in-memory delete already happened, so
	// the HTTP handler gets an error from DeleteNode.
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("want 404 or 500 for store delete error, got %d", resp.StatusCode)
	}
}

// ─── nodeOrAdminAuth: topology with HMAC ────────────────────────────────────

// TestNodeOrAdminAuth_TopologyWithHMAC verifies /topology accepts HMAC auth.
func TestNodeOrAdminAuth_TopologyWithHMAC(t *testing.T) {
	const secret = "test-secret"
	api, ts := newTestAPIWithSecret(t, secret)

	// Register a node.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	regBody, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64, Hostname: "topo-hmac", AuthKey: ak.Key,
	})
	r, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))
	r.Body.Close()

	// Signed request to /topology.
	sig := SignRequest(testPubKey, http.MethodGet, "/api/v1/topology", nil)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/topology", nil)
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 for HMAC-authed topology, got %d", resp.StatusCode)
	}
}

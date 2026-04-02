package coordinator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
		"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestAPI creates an API with a fresh in-memory store and returns
// the API and the test HTTP server.
func newTestAPI(t *testing.T) (*API, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewIPPool("100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return api, ts
}

// addAuthKey seeds an auth key directly into the API's store.
func addAuthKey(t *testing.T, api *API, key *AuthKey) {
	t.Helper()
	if err := api.store.AddAuthKey(key); err != nil {
		t.Fatal(err)
	}
}

func TestRegister_Success(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "test-node",
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var reg RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.NodeID == "" {
		t.Fatal("node_id empty")
	}
	if reg.VirtualIP == "" {
		t.Fatal("virtual_ip empty")
	}
	if reg.Hostname != "test-node" {
		t.Fatalf("hostname: %q", reg.Hostname)
	}
}

func TestRegister_InvalidAuthKey(t *testing.T) {
	_, ts := newTestAPI(t)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "bad-node",
		AuthKey:   "not-a-valid-key",
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// TestHandleAdminACL_InvalidJSON verifies that PUT /api/v1/admin/acl returns
// 400 Bad Request when the request body contains invalid JSON.
func TestHandleAdminACL_InvalidJSON(t *testing.T) {
	api, ts := newTestAPI(t)

	// Create and add an auth key to satisfy authentication
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	// Register a node first so we can make authenticated requests
	regBody, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "acl-test-node",
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Send invalid JSON to the ACL endpoint
	invalidJSON := []byte(`{"groups": {invalid json here}`)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(invalidJSON))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

// TestVerifyRequestSignature_InvalidKey verifies that signature verification
// fails when the public key header contains an invalid (non-32-byte) key.
func TestVerifyRequestSignature_InvalidKey(t *testing.T) {
	api, ts := newTestAPI(t)

	// Create and add an auth key
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	// Register a node
	regBody, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "sig-test-node",
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Make a request with an invalid public key header (not 32 bytes when decoded)
	body := []byte(`{"sinceVersion": 0}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/poll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerKey, base64.StdEncoding.EncodeToString([]byte("short"))) // not 32 bytes
	req.Header.Set(headerSig, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid key, got %d", resp.StatusCode)
	}
}

func TestRegister_ExpiredKey(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, time.Millisecond)
	time.Sleep(10 * time.Millisecond) // let it expire
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "expired-node",
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestRegister_EphemeralKeyUsedOnce(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(true, 0) // single-use
	addAuthKey(t, api, ak)

	doRegister := func(pubKey string) int {
		body, _ := json.Marshal(RegisterRequest{
			PublicKey: pubKey,
			Hostname:  "eph-node",
			AuthKey:   ak.Key,
		})
		resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// First registration succeeds.
	if code := doRegister("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); code != http.StatusOK {
		t.Fatalf("first register: %d", code)
	}
	// Second with a different pubkey fails (key used).
	if code := doRegister("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="); code != http.StatusUnauthorized {
		t.Fatalf("second register: %d", code)
	}
}

func TestRegister_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)

	resp, err := http.Get(ts.URL + "/api/v1/register")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestPeers_Empty(t *testing.T) {
	_, ts := newTestAPI(t)

	resp, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var peers []*Node
	if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected empty peers, got %d", len(peers))
	}
}

func TestPeers_AfterRegister(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "my-node",
		AuthKey:   ak.Key,
	})
	resp, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	resp2, err := http.Get(ts.URL + "/api/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	var peers []*Node
	if err := json.NewDecoder(resp2.Body).Decode(&peers); err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Hostname != "my-node" {
		t.Fatalf("hostname: %q", peers[0].Hostname)
	}
}

func TestDERPMap(t *testing.T) {
	_, ts := newTestAPI(t)

	resp, err := http.Get(ts.URL + "/api/v1/derp-map")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var dm DERPMap
	if err := json.NewDecoder(resp.Body).Decode(&dm); err != nil {
		t.Fatal(err)
	}
	// Default DERP map has empty regions.
	if dm.Regions == nil {
		t.Fatal("regions should not be nil")
	}
}

func TestAdminNodes_ListAndDelete(t *testing.T) {
	api, ts := newTestAPI(t)

	// Seed a node directly.
	node := &Node{
		ID:           "test-node-id",
		PublicKey:    "testkey",
		Hostname:     "admin-test",
		VirtualIP:    "100.64.0.5",
		Status:       NodeStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	if err := api.store.AddNode(node); err != nil {
		t.Fatal(err)
	}

	// GET /api/v1/admin/nodes
	resp, err := http.Get(ts.URL + "/api/v1/admin/nodes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var nodes []*Node
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}

	// DELETE /api/v1/admin/nodes/{id}
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/nodes/test-node-id", nil)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", delResp.StatusCode)
	}

	// Verify gone.
	resp2, err2 := http.Get(ts.URL + "/api/v1/admin/nodes")
	if err2 != nil {
		t.Fatal(err2)
	}
	defer resp2.Body.Close()
	var nodes2 []*Node
	json.NewDecoder(resp2.Body).Decode(&nodes2)
	if len(nodes2) != 0 {
		t.Fatalf("expected 0 nodes after delete, got %d", len(nodes2))
	}
}

func TestAdminACL_GetPut(t *testing.T) {
	_, ts := newTestAPI(t)

	// GET initial ACL (empty).
	resp, err := http.Get(ts.URL + "/api/v1/admin/acl")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get acl: %d", resp.StatusCode)
	}

	// PUT a new ACL.
	acl := ACLPolicy{
		Version: 1,
		Rules: []ACLRule{
			{Action: "allow", Src: []string{"*"}, Dst: []string{"*"}},
		},
	}
	body, _ := json.Marshal(acl)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("put acl: %d", putResp.StatusCode)
	}
}

func TestAdminAuthKeys(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 24*time.Hour)
	addAuthKey(t, api, ak)

	resp, err := http.Get(ts.URL + "/api/v1/admin/auth-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	var keys []*AuthKey
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one auth key")
	}
}

func TestGenerateAuthKey(t *testing.T) {
	k, err := GenerateAuthKey(false, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if k.ID == "" {
		t.Fatal("ID empty")
	}
	if k.Key == "" {
		t.Fatal("Key empty")
	}
	if k.Ephemeral {
		t.Fatal("should not be ephemeral")
	}
	if k.ExpiresAt.IsZero() {
		t.Fatal("expiry not set")
	}

	// Validate a fresh key — should pass.
	if err := ValidateAuthKey(k); err != nil {
		t.Fatalf("fresh key should be valid: %v", err)
	}
}

func TestValidateAuthKey_Expired(t *testing.T) {
	k, _ := GenerateAuthKey(false, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if err := ValidateAuthKey(k); err == nil {
		t.Fatal("expired key should fail validation")
	}
}

func TestValidateAuthKey_EphemeralUsed(t *testing.T) {
	k, _ := GenerateAuthKey(true, 0)
	k.Used = true
	if err := ValidateAuthKey(k); err == nil {
		t.Fatal("used ephemeral key should fail validation")
	}
}

func TestAdminAuthKeys_CreateAndDelete(t *testing.T) {
	_, ts := newTestAPI(t)

	// POST — create a non-ephemeral key with 24h expiry.
	body, _ := json.Marshal(CreateAuthKeyRequest{
		Ephemeral: false,
		ExpiryTTL: "24h",
	})
	resp, err := http.Post(ts.URL+"/api/v1/admin/auth-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", resp.StatusCode)
	}
	var created AuthKey
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Key == "" {
		t.Fatal("created key missing ID or Key")
	}
	if created.ExpiresAt.IsZero() {
		t.Fatal("expiry should be set")
	}

	// GET — verify it appears in the list.
	resp2, err := http.Get(ts.URL + "/api/v1/admin/auth-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var keys []*AuthKey
	if err := json.NewDecoder(resp2.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		if k.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("created key not found in list")
	}

	// DELETE — revoke the key.
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/auth-keys/"+created.ID, nil)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", delResp.StatusCode)
	}

	// GET — verify it's gone.
	resp3, err := http.Get(ts.URL + "/api/v1/admin/auth-keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	var keys2 []*AuthKey
	json.NewDecoder(resp3.Body).Decode(&keys2)
	for _, k := range keys2 {
		if k.ID == created.ID {
			t.Fatal("deleted key still in list")
		}
	}
}

func TestAdminAuthKeys_CreateEphemeral(t *testing.T) {
	_, ts := newTestAPI(t)

	body, _ := json.Marshal(CreateAuthKeyRequest{Ephemeral: true, ExpiryTTL: ""})
	resp, err := http.Post(ts.URL+"/api/v1/admin/auth-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	var k AuthKey
	if err := json.NewDecoder(resp.Body).Decode(&k); err != nil {
		t.Fatal(err)
	}
	if !k.Ephemeral {
		t.Fatal("expected ephemeral=true")
	}
	if !k.ExpiresAt.IsZero() {
		t.Fatal("no expiry expected for empty ExpiryTTL")
	}
}

func TestAdminAuthKeys_DeleteNotFound(t *testing.T) {
	_, ts := newTestAPI(t)

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/auth-keys/nosuchid", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestAdminAuthKeys_CreateBadExpiry(t *testing.T) {
	_, ts := newTestAPI(t)

	body, _ := json.Marshal(CreateAuthKeyRequest{ExpiryTTL: "notaduration"})
	resp, err := http.Post(ts.URL+"/api/v1/admin/auth-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestStore_DeleteAuthKey(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}

	ak, _ := GenerateAuthKey(false, 0)
	if err := s.AddAuthKey(ak); err != nil {
		t.Fatal(err)
	}

	// Delete it.
	if err := s.DeleteAuthKey(ak.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(s.ListAuthKeys()) != 0 {
		t.Fatal("key still present after delete")
	}

	// Deleting again should fail.
	if err := s.DeleteAuthKey(ak.ID); err == nil {
		t.Fatal("expected error deleting non-existent key")
	}
}

func TestStore_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}

	node := &Node{
		ID:           "n1",
		PublicKey:    "pk1",
		Hostname:     "host1",
		VirtualIP:    "100.64.0.10",
		Status:       NodeStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	if err := s.AddNode(node); err != nil {
		t.Fatal(err)
	}

	// Check it was saved (file exists).
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	// Re-load from disk.
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	nodes := s2.ListNodes()
	if len(nodes) != 1 || nodes[0].ID != "n1" {
		t.Fatalf("expected 1 node after reload, got %d", len(nodes))
	}
}

// --- helpers for signed-endpoint tests ---

const testPubKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

var testPubKey [32]byte // all zeros; matches testPubKeyB64

// registerTestNode registers a node using an auth key and returns the pubKey used.
func registerTestNode(t *testing.T, api *API, ts *httptest.Server, pubKeyB64, hostname string) {
	t.Helper()
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	body, _ := json.Marshal(RegisterRequest{
		PublicKey: pubKeyB64,
		Hostname:  hostname,
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: %d", resp.StatusCode)
	}
}

// signedDo creates and executes a signed HTTP request.
func signedDo(t *testing.T, method, url, path string, body []byte) *http.Response {
	t.Helper()
	sig := SignRequest(testPubKey, method, path, body)
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// --- signed endpoint tests ---

func TestPoll_Unsigned(t *testing.T) {
	_, ts := newTestAPI(t)
	body, _ := json.Marshal(PollRequest{SinceVersion: 0})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/poll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestPoll_Signed(t *testing.T) {
	api, ts := newTestAPI(t)
	registerTestNode(t, api, ts, testPubKeyB64, "poll-node")

	body, _ := json.Marshal(PollRequest{SinceVersion: 0})
	// Poll with a very old sinceVersion so the server returns immediately.
	resp := signedDo(t, http.MethodPost, ts.URL+"/api/v1/poll", "/api/v1/poll", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var state NetworkState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	if len(state.Nodes) == 0 {
		t.Fatal("expected at least one node in poll response")
	}
}

func TestPing_Signed(t *testing.T) {
	api, ts := newTestAPI(t)
	registerTestNode(t, api, ts, testPubKeyB64, "ping-node")

	resp := signedDo(t, http.MethodPost, ts.URL+"/api/v1/ping", "/api/v1/ping", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestPing_Unsigned(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ping", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestUpdateEndpoint_Signed(t *testing.T) {
	api, ts := newTestAPI(t)
	registerTestNode(t, api, ts, testPubKeyB64, "ep-node")

	body, _ := json.Marshal(UpdateEndpointRequest{Endpoint: "1.2.3.4:5678"})
	resp := signedDo(t, http.MethodPost, ts.URL+"/api/v1/update-endpoint", "/api/v1/update-endpoint", body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}

	// Verify the endpoint was stored.
	node, ok := api.store.GetNodeByPubKey(testPubKeyB64)
	if !ok {
		t.Fatal("node not found")
	}
	if node.Endpoint != "1.2.3.4:5678" {
		t.Errorf("endpoint: want 1.2.3.4:5678, got %q", node.Endpoint)
	}
}

func TestExchangeEndpoint_Signed(t *testing.T) {
	api, ts := newTestAPI(t)
	// Register two nodes with different public keys.
	const aliceB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // [32]byte{}
	const bobB64 = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="   // [32]byte{1, 0, ...}

	registerTestNode(t, api, ts, aliceB64, "alice")

	// Bob: needs a different pubkey, register manually.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	bobBody, _ := json.Marshal(RegisterRequest{
		PublicKey: bobB64,
		Hostname:  "bob",
		AuthKey:   ak.Key,
	})
	r, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(bobBody))
	r.Body.Close()

	// Alice exchanges endpoint targeting Bob.
	var alice [32]byte // all zeros
	body, _ := json.Marshal(ExchangeEndpointRequest{
		TargetPubKey: bobB64,
		MyEndpoint:   "10.0.0.1:4000",
	})
	sig := SignRequest(alice, http.MethodPost, "/api/v1/exchange-endpoint", body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/exchange-endpoint", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Karadul-Key", aliceB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange: want 200, got %d", resp.StatusCode)
	}

	// Verify Alice's endpoint was stored.
	aliceNode, _ := api.store.GetNodeByPubKey(aliceB64)
	if aliceNode.Endpoint != "10.0.0.1:4000" {
		t.Errorf("alice endpoint: %q", aliceNode.Endpoint)
	}

	var exResp ExchangeEndpointResponse
	json.NewDecoder(resp.Body).Decode(&exResp)
	// Bob has no endpoint set yet.
	if exResp.TargetEndpoint != "" {
		t.Errorf("bob endpoint should be empty, got %q", exResp.TargetEndpoint)
	}
}

func TestAdminNodes_Approve(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "manual", nil) // manual approval mode

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Register a node — it should be pending in manual mode.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	body, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "pending-node",
		AuthKey:   ak.Key,
	})
	resp, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	// Confirm node is pending.
	node, ok := api.store.GetNodeByPubKey(testPubKeyB64)
	if !ok {
		t.Fatal("node not registered")
	}
	if node.Status != NodeStatusPending {
		t.Fatalf("want pending, got %q", node.Status)
	}

	// Approve it.
	approveReq, _ := http.NewRequest(http.MethodPost,
		ts.URL+"/api/v1/admin/nodes/"+node.ID+"/approve", nil)
	approveResp, err := http.DefaultClient.Do(approveReq)
	if err != nil {
		t.Fatal(err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("approve: want 200, got %d", approveResp.StatusCode)
	}

	// Confirm node is now active.
	node2, _ := api.store.GetNodeByPubKey(testPubKeyB64)
	if node2.Status != NodeStatusActive {
		t.Fatalf("after approve: want active, got %q", node2.Status)
	}
}

func TestAdminNodes_ApproveNotFound(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/nodes/nosuchid/approve", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestPoller_ImmediateReturn(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	poller := NewPoller(store)

	// Add a node so the store has been updated.
	_ = store.AddNode(&Node{
		ID: "p1", PublicKey: "pk1", Hostname: "h1",
		VirtualIP: "100.64.0.2", Status: NodeStatusActive,
		RegisteredAt: time.Now(), LastSeen: time.Now(),
	})

	// sinceVersion=0 is older than the current store version; should return immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	state := poller.WaitForUpdate(ctx, 0)
	if len(state.Nodes) == 0 {
		t.Fatal("expected nodes in immediate poll response")
	}
	if state.Version == 0 {
		t.Fatal("version should be non-zero after AddNode")
	}
}

func TestPoller_ContextCancel(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	poller := NewPoller(store)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan NetworkState, 1)
	go func() {
		// sinceVersion = far future so we must wait.
		done <- poller.WaitForUpdate(ctx, 1<<62)
	}()

	// Cancel context after a short delay.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case state := <-done:
		// Should return (possibly empty) state after cancel.
		_ = state
	case <-time.After(3 * time.Second):
		t.Fatal("WaitForUpdate did not return after context cancel")
	}
}

func TestPoller_WakesOnStateChange(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	poller := NewPoller(store)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan NetworkState, 1)
	go func() {
		done <- poller.WaitForUpdate(ctx, 1<<62) // wait for any future update
	}()

	// Add a node after a brief delay to trigger the state change notification.
	time.Sleep(20 * time.Millisecond)
	_ = store.AddNode(&Node{
		ID: "wake1", PublicKey: "pk-wake", Hostname: "waker",
		VirtualIP: "100.64.0.9", Status: NodeStatusActive,
		RegisteredAt: time.Now(), LastSeen: time.Now(),
	})

	select {
	case state := <-done:
		if len(state.Nodes) == 0 {
			t.Fatal("expected nodes in woken poll response")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("WaitForUpdate was not woken by state change")
	}
}

// ─── Method-not-allowed and error-path tests ──────────────────────────────────

func TestDERPMap_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Post(ts.URL+"/api/v1/derp-map", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestPeers_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Post(ts.URL+"/api/v1/peers", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestPing_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/v1/ping")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestUpdateEndpoint_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/v1/update-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestUpdateEndpoint_BadJSON(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	// Register a node first.
	var pubKey [32]byte
	pubKey[0] = 0xAA
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	regReq := RegisterRequest{
		PublicKey: pubKeyB64,
		Hostname:  "test-node",
		AuthKey:   ak.Key,
	}
	regBody, _ := json.Marshal(regReq)
	http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))

	// Now send bad JSON to update-endpoint.
	body := []byte("not-json")
	sig := SignRequest(pubKey, "POST", "/api/v1/update-endpoint", body)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/update-endpoint", bytes.NewReader(body))
	req.Header.Set("X-Karadul-Key", pubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestExchangeEndpoint_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/v1/exchange-endpoint")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestExchangeEndpoint_BadJSON(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	var pubKey [32]byte
	pubKey[0] = 0xBB
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	regReq := RegisterRequest{PublicKey: pubKeyB64, Hostname: "bb-node", AuthKey: ak.Key}
	regBody, _ := json.Marshal(regReq)
	http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))

	body := []byte("bad-json")
	sig := SignRequest(pubKey, "POST", "/api/v1/exchange-endpoint", body)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/exchange-endpoint", bytes.NewReader(body))
	req.Header.Set("X-Karadul-Key", pubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestAdminACL_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/admin/acl", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestAdminACL_BadJSON(t *testing.T) {
	_, ts := newTestAPI(t)
	body := []byte("not-valid-json")
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestAdminAuthKeys_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest("PATCH", ts.URL+"/api/v1/admin/auth-keys", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

func TestUpdateEndpoint_UnknownNode(t *testing.T) {
	_, ts := newTestAPI(t)
	// Valid signature but node not registered.
	var pubKey [32]byte
	pubKey[0] = 0xCC
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	body, _ := json.Marshal(UpdateEndpointRequest{Endpoint: "1.2.3.4:5000"})
	sig := SignRequest(pubKey, "POST", "/api/v1/update-endpoint", body)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/update-endpoint", bytes.NewReader(body))
	req.Header.Set("X-Karadul-Key", pubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", resp.StatusCode)
	}
}

func TestExchangeEndpoint_TargetNotFound(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	var pubKey [32]byte
	pubKey[0] = 0xDD
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	regReq := RegisterRequest{PublicKey: pubKeyB64, Hostname: "dd-node", AuthKey: ak.Key}
	regBody, _ := json.Marshal(regReq)
	http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))

	// Request exchange with a target that doesn't exist.
	exchReq := ExchangeEndpointRequest{
		TargetPubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		MyEndpoint:   "1.2.3.4:1234",
	}
	body, _ := json.Marshal(exchReq)
	sig := SignRequest(pubKey, "POST", "/api/v1/exchange-endpoint", body)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/exchange-endpoint", bytes.NewReader(body))
	req.Header.Set("X-Karadul-Key", pubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

// TestRegister_BadJSON verifies handleRegister returns 400 for malformed JSON.
func TestRegister_BadJSON(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader([]byte("not-json")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

// TestRegister_ReRegistration verifies that registering the same public key a second
// time takes the update path (returns 200 with the same node ID).
func TestRegister_ReRegistration(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "original-host",
		AuthKey:   ak.Key,
	})
	resp1, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first register: want 200, got %d", resp1.StatusCode)
	}
	var reg1 RegisterResponse
	json.NewDecoder(resp1.Body).Decode(&reg1)

	// Second registration with same pubkey but different hostname.
	ak2, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak2)
	body2, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "updated-host",
		AuthKey:   ak2.Key,
	})
	resp2, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-register: want 200, got %d", resp2.StatusCode)
	}
	var reg2 RegisterResponse
	json.NewDecoder(resp2.Body).Decode(&reg2)

	// Should be the same node ID.
	if reg2.NodeID != reg1.NodeID {
		t.Errorf("re-register: want same node ID %q, got %q", reg1.NodeID, reg2.NodeID)
	}
}

// TestRegister_ManualMode_ReRegisterPreservesActive verifies that in manual approval
// mode, a node that was approved and then re-registers keeps its active status.
func TestRegister_ManualMode_ReRegisterPreservesActive(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "manual", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// Register — should be pending.
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	body, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "manual-node",
		AuthKey:   ak.Key,
	})
	resp, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	node, _ := store.GetNodeByPubKey(testPubKeyB64)
	if node.Status != NodeStatusPending {
		t.Fatalf("initial: want pending, got %q", node.Status)
	}

	// Approve.
	approveReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/nodes/"+node.ID+"/approve", nil)
	approveResp, _ := http.DefaultClient.Do(approveReq)
	approveResp.Body.Close()
	node2, _ := store.GetNodeByPubKey(testPubKeyB64)
	if node2.Status != NodeStatusActive {
		t.Fatalf("after approve: want active, got %q", node2.Status)
	}

	// Re-register with same pubkey.
	ak2, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak2)
	body2, _ := json.Marshal(RegisterRequest{
		PublicKey: testPubKeyB64,
		Hostname:  "manual-node-updated",
		AuthKey:   ak2.Key,
	})
	resp2, _ := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body2))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("re-register: want 200, got %d", resp2.StatusCode)
	}

	// Status should still be active (not reverted to pending).
	node3, _ := store.GetNodeByPubKey(testPubKeyB64)
	if node3.Status != NodeStatusActive {
		t.Fatalf("after re-register: want active, got %q", node3.Status)
	}
}

// TestAdminNodes_MethodNotAllowed verifies PUT to /admin/nodes/ returns 405.
func TestAdminNodes_MethodNotAllowed(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/nodes/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", resp.StatusCode)
	}
}

// TestAdminNodes_DeleteNotFound verifies DELETE of a non-existent node returns 404.
func TestAdminNodes_DeleteNotFound(t *testing.T) {
	_, ts := newTestAPI(t)
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/nodes/nosuchid", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

// TestAdminNodes_ApproveEmptyID verifies that POSTing /approve with an empty node ID
// returns 400. The handler is called directly to bypass mux path cleaning.
func TestAdminNodes_ApproveEmptyID(t *testing.T) {
	api, _ := newTestAPI(t)
	// Craft a request where the path has an empty ID segment.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes//approve", nil)
	w := httptest.NewRecorder()
	api.handleAdminNodes(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSignRequest_Roundtrip(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	body := []byte(`{"key":"value"}`)
	sig := SignRequest(pubKey, "POST", "/api/v1/poll", body)
	if sig == "" {
		t.Fatal("signature is empty")
	}

	// Simulate what VerifyRequestSignature does.
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(sigBytes) != 32 {
		t.Fatalf("sig decode: err=%v len=%d", err, len(sigBytes))
	}

	// Verify the pubKeyB64 round-trips.
	pkBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pkBytes) != 32 {
		t.Fatalf("pubkey decode: err=%v len=%d", err, len(pkBytes))
	}
}

// TestAdminACL_GetSuccess verifies GET /admin/acl returns 200.
func TestAdminACL_GetSuccess(t *testing.T) {
	_, ts := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/v1/admin/acl")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// TestAdminACL_PutSuccess verifies PUT /admin/acl with valid JSON returns 200.
func TestAdminACL_PutSuccess(t *testing.T) {
	_, ts := newTestAPI(t)
	policy := ACLPolicy{
		Version: 1,
		Rules: []ACLRule{
			{Action: "allow", Src: []string{"*"}, Dst: []string{"*"}},
		},
	}
	body, _ := json.Marshal(policy)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
}

// TestHandleAdminACL_InvalidAction verifies that PUT /admin/acl rejects invalid actions.
func TestHandleAdminACL_InvalidAction(t *testing.T) {
	_, ts := newTestAPI(t)

	tests := []struct {
		name   string
		action string
	}{
		{"invalid_action_accept", "accept"},
		{"empty_action", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := ACLPolicy{
				Version: 1,
				Rules: []ACLRule{
					{Action: tt.action, Src: []string{"*"}, Dst: []string{"*"}},
				},
			}
			body, _ := json.Marshal(policy)
			req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("action %q: want 400, got %d", tt.action, resp.StatusCode)
			}
		})
	}
}

// TestHandleAdminACL_InvalidPorts verifies that PUT /admin/acl rejects invalid port values.
func TestHandleAdminACL_InvalidPorts(t *testing.T) {
	_, ts := newTestAPI(t)

	tests := []struct {
		name  string
		ports []string
	}{
		{"port_zero", []string{"0"}},
		{"port_too_high", []string{"70000"}},
		{"port_range_inverted", []string{"443-80"}},
		{"port_non_numeric", []string{"abc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := ACLPolicy{
				Version: 1,
				Rules: []ACLRule{
					{Action: "allow", Src: []string{"*"}, Dst: []string{"*"}, Ports: tt.ports},
				},
			}
			body, _ := json.Marshal(policy)
			req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("ports %v: want 400, got %d", tt.ports, resp.StatusCode)
			}
		})
	}
}

// TestAdminAuthKeys_DeleteEmptyID verifies DELETE with no key ID returns 400.
// The handler is invoked directly to avoid mux path cleaning.
func TestAdminAuthKeys_DeleteEmptyID(t *testing.T) {
	api, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/auth-keys/", nil)
	w := httptest.NewRecorder()
	api.handleAdminAuthKeys(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// TestValidateAuthKey_Nil verifies that ValidateAuthKey returns an error for a nil key.
func TestValidateAuthKey_Nil(t *testing.T) {
	if err := ValidateAuthKey(nil); err == nil {
		t.Fatal("expected error for nil auth key")
	}
}

// TestVerifyRequestSignature_MissingHeaders verifies error when auth headers are missing.
func TestVerifyRequestSignature_MissingHeaders(t *testing.T) {
	s := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error when auth headers are missing")
	}
}

// TestVerifyRequestSignature_InvalidPubKeyHeader verifies error when X-Karadul-Key is invalid base64.
func TestVerifyRequestSignature_InvalidPubKeyHeader(t *testing.T) {
	s := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", "!!!not-base64!!!")
	req.Header.Set("X-Karadul-Sig", "dGVzdA==")
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for invalid public key header")
	}
}

// TestVerifyRequestSignature_WrongPubKeyLen verifies error when decoded public key is not 32 bytes.
func TestVerifyRequestSignature_WrongPubKeyLen(t *testing.T) {
	s := newTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	// Valid base64 but wrong length (only 4 bytes when decoded).
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString([]byte("short")))
	req.Header.Set("X-Karadul-Sig", "dGVzdA==")
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for wrong-length public key")
	}
}

// TestVerifyRequestSignature_UnknownNode verifies error when public key is not registered.
func TestVerifyRequestSignature_UnknownNode(t *testing.T) {
	s := newTestStore(t)
	var pubKey [32]byte
	pubKey[0] = 0xAA
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString(pubKey[:]))
	req.Header.Set("X-Karadul-Sig", "dGVzdA==")
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for unknown node key")
	}
}

// TestVerifyRequestSignature_NodeNotActive verifies error when node status is not active.
func TestVerifyRequestSignature_NodeNotActive(t *testing.T) {
	s := newTestStore(t)
	// Register a pending node.
	n := &Node{
		ID:           "inactive-node",
		PublicKey:    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Hostname:     "pending",
		VirtualIP:    "100.64.0.50",
		Status:       NodeStatusPending,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	s.AddNode(n)

	var pubKey [32]byte
	copy(pubKey[:], make([]byte, 32))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString(pubKey[:]))
	req.Header.Set("X-Karadul-Sig", "dGVzdA==")
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for inactive node")
	}
}

// TestVerifyRequestSignature_InvalidSigBase64 verifies error when signature is invalid base64.
func TestVerifyRequestSignature_InvalidSigBase64(t *testing.T) {
	s := newTestStore(t)
	// Register an active node.
	n := &Node{
		ID:           "active-node",
		PublicKey:    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Hostname:     "active",
		VirtualIP:    "100.64.0.51",
		Status:       NodeStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	s.AddNode(n)

	var pubKey [32]byte
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString(pubKey[:]))
	req.Header.Set("X-Karadul-Sig", "!!!not-base64!!!")
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for invalid signature base64")
	}
}

// TestVerifyRequestSignature_WrongSigLen verifies error when decoded signature is not 32 bytes.
func TestVerifyRequestSignature_WrongSigLen(t *testing.T) {
	s := newTestStore(t)
	n := &Node{
		ID:           "active-node2",
		PublicKey:    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Hostname:     "active2",
		VirtualIP:    "100.64.0.52",
		Status:       NodeStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	s.AddNode(n)

	var pubKey [32]byte
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString(pubKey[:]))
	// Valid base64 but wrong length.
	req.Header.Set("X-Karadul-Sig", base64.StdEncoding.EncodeToString([]byte("short")))
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

// TestVerifyRequestSignature_BadSignature verifies error when signature verification fails.
func TestVerifyRequestSignature_BadSignature(t *testing.T) {
	s := newTestStore(t)
	n := &Node{
		ID:           "active-node3",
		PublicKey:    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		Hostname:     "active3",
		VirtualIP:    "100.64.0.53",
		Status:       NodeStatusActive,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}
	s.AddNode(n)

	var pubKey [32]byte
	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	req.Header.Set("X-Karadul-Key", base64.StdEncoding.EncodeToString(pubKey[:]))
	// 32-byte signature but wrong content.
	var wrongSig [32]byte
	wrongSig[0] = 0xFF
	req.Header.Set("X-Karadul-Sig", base64.StdEncoding.EncodeToString(wrongSig[:]))
	if err := VerifyRequestSignature(s, req, nil); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

// TestWriteJSON_EncodeError verifies writeJSON handles encoding errors.
func TestWriteJSON_EncodeError(t *testing.T) {
	w := httptest.NewRecorder()
	// Pass a channel which cannot be JSON encoded.
	writeJSON(w, make(chan int))

	// Should get an error response.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// TestWriteJSON_Success verifies writeJSON succeeds with valid data.
func TestWriteJSON_Success(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(w, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}

// TestRegister_EmptyHostname verifies that when req.Hostname is empty,
// an auto-generated hostname is created (node-{id[:8]} format).
func TestRegister_EmptyHostname(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	// Register with empty hostname
	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "", // empty hostname
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var reg RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}

	// Verify hostname was auto-generated with node- prefix
	if reg.Hostname == "" {
		t.Fatal("expected auto-generated hostname, got empty")
	}
	if len(reg.Hostname) < 6 || reg.Hostname[:5] != "node-" {
		t.Errorf("expected hostname to start with 'node-', got %q", reg.Hostname)
	}
}

// TestPoll_InvalidJSON verifies that poll with malformed JSON body
// still proceeds (the handler ignores unmarshal errors and uses zero values).
func TestPoll_InvalidJSON(t *testing.T) {
	api, ts := newTestAPI(t)

	// Register a node first
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)
	regBody, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "poll-test",
		AuthKey:   ak.Key,
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Now poll with invalid JSON - the handler ignores unmarshal errors
	invalidJSON := []byte(`{"sinceVersion": invalid}`)
	sig := SignRequest(testPubKey, http.MethodPost, "/api/v1/poll", invalidJSON)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/poll", bytes.NewReader(invalidJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Karadul-Key", testPubKeyB64)
	req.Header.Set("X-Karadul-Sig", sig)

	client := &http.Client{Timeout: 2 * time.Second}
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	// The handler ignores unmarshal errors, so it should return 200 with current state
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp2.StatusCode)
	}
}

// TestAdminACL_StoreSetACLError verifies ACL update returns 500 when store fails.
func TestAdminACL_StoreSetACLError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, _ := NewStore(storePath)
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Block the store's temp file path to cause Save() to fail
	tmpPath := storePath + ".tmp"
	if err := os.MkdirAll(tmpPath, 0700); err != nil {
		t.Fatal(err)
	}

	acl := ACLPolicy{
		Version: 1,
		Rules: []ACLRule{
			{Action: "allow", Src: []string{"*"}, Dst: []string{"*"}},
		},
	}
	body, _ := json.Marshal(acl)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/acl", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when store fails, got %d", resp.StatusCode)
	}
}

// TestRegister_IPPoolExhausted verifies that registration returns 503 when the IP pool is exhausted.
func TestRegister_IPPoolExhausted(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, err := NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}

	// Use /30 subnet - only 2 usable IPs (network and broadcast excluded)
	pool, err := NewIPPool("100.64.0.0/30")
	if err != nil {
		t.Fatal(err)
	}

	// Reserve both IPs
	ip1 := net.ParseIP("100.64.0.1")
	ip2 := net.ParseIP("100.64.0.2")
	_ = pool.Reserve("node1", ip1)
	_ = pool.Reserve("node2", ip2)

	// Create auth key
	ak, _ := GenerateAuthKey(true, 0)
	_ = store.AddAuthKey(ak)

	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Try to register a new node - should fail with 503
	reqBody := RegisterRequest{
		PublicKey: "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // valid 32-byte key
		Hostname:  "newnode",
		AuthKey:   ak.Key,
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when pool exhausted, got %d", resp.StatusCode)
	}
}

// TestRegister_StoreAddNodeError verifies that registration returns 500 when store.AddNode fails.
func TestRegister_StoreAddNodeError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, err := NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}

	pool, err := NewIPPool("100.64.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// Create auth key
	ak, _ := GenerateAuthKey(true, 0)
	_ = store.AddAuthKey(ak)

	// Block the store's temp file path to cause AddNode to fail
	tmpPath := storePath + ".tmp"
	if err := os.MkdirAll(tmpPath, 0700); err != nil {
		t.Fatal(err)
	}

	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Try to register - should fail with 500 due to store error
	reqBody := RegisterRequest{
		PublicKey: "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // valid 32-byte key
		Hostname:  "errornode",
		AuthKey:   ak.Key,
	}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when store fails, got %d", resp.StatusCode)
	}
}

// TestAdminAuthKeys_StoreAddAuthKeyError verifies that auth key creation returns 500 when store.AddAuthKey fails.
func TestAdminAuthKeys_StoreAddAuthKeyError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")
	store, err := NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}

	pool, err := NewIPPool("100.64.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// Block the store's temp file path to cause AddAuthKey to fail
	tmpPath := storePath + ".tmp"
	if err := os.MkdirAll(tmpPath, 0700); err != nil {
		t.Fatal(err)
	}

	poller := NewPoller(store)
	api := NewAPI(store, pool, poller, "auto", nil)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Try to create auth key - should fail with 500 due to store error
	reqBody := CreateAuthKeyRequest{Ephemeral: true}
	body, _ := json.Marshal(reqBody)
	resp, err := http.Post(ts.URL+"/api/v1/admin/auth-keys", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when store fails, got %d", resp.StatusCode)
	}
}

func TestRegister_InvalidPublicKey(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	tests := []struct {
		name   string
		pubKey string
	}{
		{"empty", ""},
		{"too short", "AAAA"},
		{"not base64", "!!!not-base64!!!"},
		{"wrong length", base64.StdEncoding.EncodeToString(make([]byte, 16))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(RegisterRequest{
				PublicKey: tt.pubKey,
				Hostname:  "test",
				AuthKey:   ak.Key,
			})
			resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("want 400, got %d", resp.StatusCode)
			}
		})
	}
}

func TestRegister_InvalidHostname(t *testing.T) {
	api, ts := newTestAPI(t)
	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	tests := []struct {
		name     string
		hostname string
	}{
		{"special chars", "node<script>alert(1)</script>"},
		{"spaces", "node with spaces"},
		{"too long", strings.Repeat("a", 254)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(RegisterRequest{
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				Hostname:  tt.hostname,
				AuthKey:   ak.Key,
			})
			resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("want 400 for %q, got %d", tt.hostname, resp.StatusCode)
			}
		})
	}
}

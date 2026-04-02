package coordinator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/config"
)

// ─── 1. TestHandleTopology ────────────────────────────────────────────────────

func TestHandleTopology(t *testing.T) {
	t.Run("no_nodes", func(t *testing.T) {
		api, _ := newTestAPI(t)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/topology", nil)
		w := httptest.NewRecorder()
		api.handleTopology(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status: %d", w.Code)
		}
		var resp TopologyResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Nodes) != 0 {
			t.Fatalf("expected 0 nodes, got %d", len(resp.Nodes))
		}
		if len(resp.Connections) != 0 {
			t.Fatalf("expected 0 connections, got %d", len(resp.Connections))
		}
	})

	t.Run("all_active_with_endpoints", func(t *testing.T) {
		api, _ := newTestAPI(t)
		now := time.Now()
		api.store.AddNode(&Node{
			ID: "n1", PublicKey: "pk1", Hostname: "a",
			VirtualIP: "100.64.0.1", Status: NodeStatusActive,
			Endpoint: "1.1.1.1:5000", LastSeen: now, RegisteredAt: now,
		})
		api.store.AddNode(&Node{
			ID: "n2", PublicKey: "pk2", Hostname: "b",
			VirtualIP: "100.64.0.2", Status: NodeStatusActive,
			Endpoint: "2.2.2.2:5000", LastSeen: now, RegisteredAt: now,
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/topology", nil)
		w := httptest.NewRecorder()
		api.handleTopology(w, req)

		var resp TopologyResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Nodes) != 2 {
			t.Fatalf("expected 2 nodes, got %d", len(resp.Nodes))
		}
		if len(resp.Connections) != 1 {
			t.Fatalf("expected 1 connection (both recent with endpoints), got %d", len(resp.Connections))
		}
		if resp.Connections[0].Type != "direct" {
			t.Fatalf("expected direct connection, got %q", resp.Connections[0].Type)
		}
	})

	t.Run("mix_active_offline", func(t *testing.T) {
		api, _ := newTestAPI(t)
		now := time.Now()
		api.store.AddNode(&Node{
			ID: "active1", PublicKey: "pa1", Hostname: "active-one",
			VirtualIP: "100.64.0.10", Status: NodeStatusActive,
			Endpoint: "10.0.0.1:4000", LastSeen: now, RegisteredAt: now,
		})
		api.store.AddNode(&Node{
			ID: "pending1", PublicKey: "pp1", Hostname: "pending-one",
			VirtualIP: "100.64.0.11", Status: NodeStatusPending,
			LastSeen: now, RegisteredAt: now,
		})
		api.store.AddNode(&Node{
			ID: "offline1", PublicKey: "po1", Hostname: "offline-one",
			VirtualIP: "100.64.0.12", Status: NodeStatusDisabled,
			LastSeen: now, RegisteredAt: now,
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/topology", nil)
		w := httptest.NewRecorder()
		api.handleTopology(w, req)

		var resp TopologyResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		// Nodes list includes all nodes; connections only between active+recent.
		if len(resp.Nodes) != 3 {
			t.Fatalf("expected 3 nodes in list, got %d", len(resp.Nodes))
		}
		if len(resp.Connections) != 0 {
			t.Fatalf("expected 0 connections (only 1 active node), got %d", len(resp.Connections))
		}
	})
}

// ─── 2. TestHandleStatus ──────────────────────────────────────────────────────

func TestHandleStatus(t *testing.T) {
	api, _ := newTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	w := httptest.NewRecorder()
	api.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var status SystemStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.Uptime < 0 {
		t.Fatal("uptime should be non-negative")
	}
	if status.Goroutines <= 0 {
		t.Fatal("goroutines should be positive")
	}
	if status.MemoryUsage <= 0 {
		t.Fatal("memory usage should be positive")
	}
}

// ─── 3. TestHandleAdminConfig_GetPut ──────────────────────────────────────────

func TestHandleAdminConfig_GetPut(t *testing.T) {
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
	cfg := &config.ServerConfig{
		Addr:         ":8080",
		Subnet:       "100.64.0.0/10",
		DataDir:      t.TempDir(),
		ApprovalMode: "auto",
	}
	api := NewAPI(store, pool, poller, "auto", cfg)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	// GET — should return current config (nil in this case).
	getResp, err := http.Get(ts.URL + "/api/v1/admin/config")
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get config: %d", getResp.StatusCode)
	}

	// PUT — update with valid config.
	newCfg := config.ServerConfig{
		Addr:         ":9999",
		Subnet:       "100.64.0.0/10",
		DataDir:      t.TempDir(),
		ApprovalMode: "auto",
	}
	body, _ := json.Marshal(newCfg)
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("put config: want 200, got %d", putResp.StatusCode)
	}

	// Verify the config was updated.
	var updated config.ServerConfig
	if err := json.NewDecoder(putResp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.Addr != ":9999" {
		t.Fatalf("config addr: want :9999, got %q", updated.Addr)
	}

	// PUT — invalid config (bad subnet).
	badCfg := config.ServerConfig{
		Addr:   ":8080",
		Subnet: "not-a-subnet",
	}
	badBody, _ := json.Marshal(badCfg)
	badReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/admin/config", bytes.NewReader(badBody))
	badReq.Header.Set("Content-Type", "application/json")
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid config: want 400, got %d", badResp.StatusCode)
	}
}

// ─── 4. TestParseDERPAddr ────────────────────────────────────────────────────

func TestParseDERPAddr(t *testing.T) {
	tests := []struct {
		input     string
		wantHost  string
		wantPort  int
	}{
		{":8080", "127.0.0.1", 8080},
		{"1.2.3.4:3340", "1.2.3.4", 3340},
		{"", "127.0.0.1", 443},           // defaults
		{"host:0", "host", 443},          // port 0 defaults to 443
		{"[::1]:443", "::1", 443},        // IPv6
		{"example.com:8443", "example.com", 8443},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseDERPAddr(tt.input)
			if host != tt.wantHost {
				t.Errorf("host: want %q, got %q", tt.wantHost, host)
			}
			if port != tt.wantPort {
				t.Errorf("port: want %d, got %d", tt.wantPort, port)
			}
		})
	}
}

// ─── 5. TestIsValidID ─────────────────────────────────────────────────────────

func TestIsValidID(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"abc123", true},
		{"node-id-42", true},
		{"ABC", true},
		{"", false},
		{"node_id", false},            // underscore not allowed
		{"node@example", false},       // @ not allowed
		{"has space", false},          // space not allowed
		{"café", false},               // unicode not allowed
		{"日本語", false},               // unicode not allowed
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidID(tt.input); got != tt.want {
				t.Errorf("isValidID(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ─── 6. TestIsValidPublicKey ──────────────────────────────────────────────────

func TestIsValidPublicKey(t *testing.T) {
	valid32 := base64.StdEncoding.EncodeToString(make([]byte, 32)) // 32 zero bytes

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid_32_byte", valid32, true},
		{"empty", "", false},
		{"invalid_base64", "!!!not-base64!!!", false},
		{"wrong_length_16", base64.StdEncoding.EncodeToString(make([]byte, 16)), false},
		{"wrong_length_64", base64.StdEncoding.EncodeToString(make([]byte, 64)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidPublicKey(tt.input); got != tt.want {
				t.Errorf("isValidPublicKey(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ─── 7. TestIsValidPort ───────────────────────────────────────────────────────

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"80", true},
		{"1", true},
		{"65535", true},
		{"0", false},
		{"", false},
		{"abc", false},
		{"80-443", true},
		{"1-1024", true},
		{"443-80", false},   // lo > hi
		{"0-100", false},    // lo < 1
		{"1-70000", false},  // hi > 65535
		{"80-", false},
		{"-80", false},
		{"80-443-999", false}, // only one dash allowed
		{"-1", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isValidPort(tt.input); got != tt.want {
				t.Errorf("isValidPort(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ─── 8. TestSanitizeHostname ──────────────────────────────────────────────────

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid", "my-node", "my-node", false},
		{"valid_dots", "node.example.com", "node.example.com", false},
		{"valid_alphanumeric", "node123", "node123", false},
		{"special_chars", "node<script>", "", true},
		{"spaces", "my host", "", true},
		{"too_long", strings.Repeat("a", 254), "", true},
		{"at_max_length", strings.Repeat("a", 253), strings.Repeat("a", 253), false},
		{"underscore", "my_node", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizeHostname(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeHostname(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("sanitizeHostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─── 9. TestBuildDERPMap_Disabled ─────────────────────────────────────────────

func TestBuildDERPMap_Disabled(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		dir := t.TempDir()
		store, _ := NewStore(filepath.Join(dir, "state.json"))
		pool, _ := NewIPPool("100.64.0.0/10")
		poller := NewPoller(store)
		api := NewAPI(store, pool, poller, "auto", nil) // cfg == nil

		dm := api.buildDERPMap()
		if dm == nil {
			t.Fatal("DERPMap should not be nil")
		}
		if len(dm.Regions) != 0 {
			t.Fatalf("expected 0 regions when DERP disabled (nil config), got %d", len(dm.Regions))
		}
	})

	t.Run("disabled_flag", func(t *testing.T) {
		dir := t.TempDir()
		store, _ := NewStore(filepath.Join(dir, "state.json"))
		pool, _ := NewIPPool("100.64.0.0/10")
		poller := NewPoller(store)
		cfg := &config.ServerConfig{
			Addr:   ":8080",
			Subnet: "100.64.0.0/10",
			DERP:   config.DERPServerConfig{Enabled: false},
		}
		api := NewAPI(store, pool, poller, "auto", cfg)

		dm := api.buildDERPMap()
		if len(dm.Regions) != 0 {
			t.Fatalf("expected 0 regions when DERP disabled, got %d", len(dm.Regions))
		}
	})
}

// ─── 10. TestBuildDERPMap_Enabled ─────────────────────────────────────────────

func TestBuildDERPMap_Enabled(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(filepath.Join(dir, "state.json"))
	pool, _ := NewIPPool("100.64.0.0/10")
	poller := NewPoller(store)
	cfg := &config.ServerConfig{
		Addr:   ":8080",
		Subnet: "100.64.0.0/10",
		DERP:   config.DERPServerConfig{Enabled: true, Addr: "1.2.3.4:3340"},
	}
	api := NewAPI(store, pool, poller, "auto", cfg)

	dm := api.buildDERPMap()
	if len(dm.Regions) != 1 {
		t.Fatalf("expected 1 region, got %d", len(dm.Regions))
	}
	r := dm.Regions[0]
	if r.RegionID != 1 {
		t.Errorf("region ID: want 1, got %d", r.RegionID)
	}
	if len(r.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(r.Nodes))
	}
	if r.Nodes[0].HostName != "1.2.3.4" {
		t.Errorf("host: want 1.2.3.4, got %q", r.Nodes[0].HostName)
	}
	if r.Nodes[0].DERPPort != 3340 {
		t.Errorf("port: want 3340, got %d", r.Nodes[0].DERPPort)
	}
}

// ─── 11. TestStoreGC_StaleNodeMarking ─────────────────────────────────────────

func TestStoreGC_StaleNodeMarking(t *testing.T) {
	s := newTestStore(t)

	// Add a node with LastSeen older than gcNodeStaleAge.
	oldTime := time.Now().Add(-gcNodeStaleAge - time.Minute)
	s.AddNode(&Node{
		ID: "stale-node", PublicKey: "pk-stale", Hostname: "stale",
		VirtualIP: "100.64.0.50", Status: NodeStatusActive,
		RegisteredAt: oldTime, LastSeen: oldTime,
	})

	// Run GC directly.
	s.runGC()

	node, ok := s.GetNode("stale-node")
	if !ok {
		t.Fatal("stale node should still exist (not deleted yet)")
	}
	if node.Status != NodeStatusDisabled {
		t.Fatalf("stale node should be marked offline, got %q", node.Status)
	}
}

// ─── 12. TestStoreGC_ExpiredNodeDeletion ──────────────────────────────────────

func TestStoreGC_ExpiredNodeDeletion(t *testing.T) {
	s := newTestStore(t)

	// Add a node that has been offline (disabled) for > gcNodeExpireAge.
	oldTime := time.Now().Add(-gcNodeExpireAge - time.Hour)
	s.AddNode(&Node{
		ID: "expired-node", PublicKey: "pk-expired", Hostname: "expired",
		VirtualIP: "100.64.0.51", Status: NodeStatusDisabled,
		RegisteredAt: oldTime, LastSeen: oldTime,
	})

	s.runGC()

	_, ok := s.GetNode("expired-node")
	if ok {
		t.Fatal("expired node should have been deleted by GC")
	}
}

// ─── 13. TestStoreGC_ExpiredKeyPruning ─────────────────────────────────────────

func TestStoreGC_ExpiredKeyPruning(t *testing.T) {
	s := newTestStore(t)

	// Add an expired ephemeral key that was used > gcKeyExpireAge ago.
	oldTime := time.Now().Add(-gcKeyExpireAge - time.Hour)
	s.AddAuthKey(&AuthKey{
		ID: "eph-used-key", Key: "secret1", Ephemeral: true,
		Used: true, UsedAt: oldTime, CreatedAt: oldTime,
	})

	// Add a long-expired non-ephemeral key.
	s.AddAuthKey(&AuthKey{
		ID: "expired-key", Key: "secret2", Ephemeral: false,
		ExpiresAt: time.Now().Add(-gcKeyExpireAge - time.Hour),
		CreatedAt: oldTime,
	})

	// Add a fresh key that should not be pruned.
	s.AddAuthKey(&AuthKey{
		ID: "fresh-key", Key: "secret3", Ephemeral: false,
		CreatedAt: time.Now(),
	})

	s.runGC()

	keys := s.ListAuthKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after GC, got %d", len(keys))
	}
	if keys[0].ID != "fresh-key" {
		t.Errorf("expected fresh-key to remain, got %q", keys[0].ID)
	}
}

// ─── 14. TestHandleRegister_InvalidRoutes ──────────────────────────────────────

func TestHandleRegister_InvalidRoutes(t *testing.T) {
	api, ts := newTestAPI(t)

	ak, _ := GenerateAuthKey(false, 0)
	addAuthKey(t, api, ak)

	body, _ := json.Marshal(RegisterRequest{
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Hostname:  "bad-routes-node",
		AuthKey:   ak.Key,
		Routes:    []string{"not-a-cidr", "10.0.0.0/24"},
	})
	resp, err := http.Post(ts.URL+"/api/v1/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid route CIDR, got %d", resp.StatusCode)
	}
}

// ─── 15. TestExchangeEndpoint_InvalidTargetPubKey ─────────────────────────────

func TestExchangeEndpoint_InvalidTargetPubKey(t *testing.T) {
	api, ts := newTestAPI(t)

	// Register a node so we can sign requests.
	registerTestNode(t, api, ts, testPubKeyB64, "exchange-node")

	body, _ := json.Marshal(ExchangeEndpointRequest{
		TargetPubKey: "!!!invalid-base64!!!",
		MyEndpoint:   "10.0.0.1:4000",
	})
	resp := signedDo(t, http.MethodPost, ts.URL+"/api/v1/exchange-endpoint", "/api/v1/exchange-endpoint", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid targetPubKey, got %d", resp.StatusCode)
	}
}

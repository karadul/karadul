package node

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/coordinator"
	"github.com/karadul/karadul/internal/crypto"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/mesh"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.NodeConfig{
		ServerURL: "http://127.0.0.1:8080",
		Hostname:  "test-node",
		AuthKey:   "test-auth-key",
	}
	log := klog.New(nil, klog.LevelDebug, klog.FormatText)
	e := NewEngine(cfg, kp, log)
	// Initialise a mesh manager so tests that call LocalStatus / handleAPIMetrics
	// don't panic on nil.
	e.manager = mesh.NewManager(log, nil)
	return e
}

// ─── Session management tests ────────────────────────────────────────────────

func TestBuildSession(t *testing.T) {
	e := testEngine(t)

	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i)
		recvKey[i] = byte(i + 1)
	}

	var remotePub crypto.Key
	for i := range remotePub {
		remotePub[i] = byte(i + 10)
	}

	ep := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	ps := e.buildSession(remotePub, sendKey, recvKey, 1, 2, ep)

	if ps == nil {
		t.Fatal("expected non-nil peerSession")
	}
	if ps.localID != 1 {
		t.Errorf("localID: got %d, want 1", ps.localID)
	}
	if ps.receiverID != 2 {
		t.Errorf("receiverID: got %d, want 2", ps.receiverID)
	}

	// Verify maps.
	e.mu.RLock()
	_, ok := e.sessions[remotePub]
	byIDSession, ok2 := e.byID[1]
	e.mu.RUnlock()
	if !ok {
		t.Error("session not in sessions map")
	}
	if !ok2 || byIDSession != ps {
		t.Error("session not in byID map")
	}
}

func TestRekeyPeer_CleansByID(t *testing.T) {
	e := testEngine(t)

	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	peer := mesh.NewPeer(pubKey, "test-peer", "node-1", net.ParseIP("100.64.0.2"))

	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i)
		recvKey[i] = byte(i + 1)
	}
	_ = e.buildSession(peer.PublicKey, sendKey, recvKey, 42, 99, nil)

	// Verify session exists.
	e.mu.RLock()
	_, ok1 := e.sessions[peer.PublicKey]
	_, ok2 := e.byID[42]
	e.mu.RUnlock()
	if !ok1 || !ok2 {
		t.Fatal("session should exist before rekey")
	}

	e.RekeyPeer(peer)

	// After RekeyPeer, both maps should be cleaned.
	e.mu.RLock()
	_, hasSession := e.sessions[peer.PublicKey]
	_, hasByID := e.byID[42]
	e.mu.RUnlock()
	if hasSession {
		t.Error("sessions map should not have old entry after RekeyPeer")
	}
	if hasByID {
		t.Error("byID map should not have old entry after RekeyPeer")
	}
}

// ─── Metrics tests ───────────────────────────────────────────────────────────

func TestMetricsAtomicCounters(t *testing.T) {
	e := testEngine(t)

	e.metricPacketsTx.Add(5)
	e.metricPacketsTx.Add(3)
	if e.metricPacketsTx.Load() != 8 {
		t.Errorf("packets tx: got %d, want 8", e.metricPacketsTx.Load())
	}

	e.metricBytesTx.Add(100)
	e.metricBytesTx.Add(200)
	if e.metricBytesTx.Load() != 300 {
		t.Errorf("bytes tx: got %d, want 300", e.metricBytesTx.Load())
	}

	e.metricPacketsRx.Add(10)
	if e.metricPacketsRx.Load() != 10 {
		t.Errorf("packets rx: got %d, want 10", e.metricPacketsRx.Load())
	}

	e.metricBytesRx.Add(42)
	if e.metricBytesRx.Load() != 42 {
		t.Errorf("bytes rx: got %d, want 42", e.metricBytesRx.Load())
	}
}

// ─── Topology / MagicDNS tests ───────────────────────────────────────────────

func TestUpdateMagicDNS(t *testing.T) {
	e := testEngine(t)

	nodes := []*coordinator.Node{
		{
			Hostname:  "node-a",
			VirtualIP: "100.64.0.2",
			Status:    coordinator.NodeStatusActive,
		},
		{
			Hostname:  "node-b",
			VirtualIP: "100.64.0.3",
			Status:    coordinator.NodeStatusActive,
		},
		{
			Hostname:  "node-pending",
			VirtualIP: "100.64.0.4",
			Status:    coordinator.NodeStatusPending,
		},
	}

	e.updateMagicDNS(nodes)

	if ip := e.magic.Lookup("node-a"); ip == nil || !ip.Equal(net.ParseIP("100.64.0.2")) {
		t.Errorf("node-a: got %v, want 100.64.0.2", ip)
	}
	if ip := e.magic.Lookup("node-b"); ip == nil || !ip.Equal(net.ParseIP("100.64.0.3")) {
		t.Errorf("node-b: got %v, want 100.64.0.3", ip)
	}
	if ip := e.magic.Lookup("node-pending"); ip != nil {
		t.Errorf("pending node should not resolve, got %v", ip)
	}
}

func TestUpdateMagicDNS_InvalidIP(t *testing.T) {
	e := testEngine(t)

	nodes := []*coordinator.Node{
		{Hostname: "bad-node", VirtualIP: "not-an-ip", Status: coordinator.NodeStatusActive},
	}
	e.updateMagicDNS(nodes)

	if ip := e.magic.Lookup("bad-node"); ip != nil {
		t.Errorf("bad IP should not resolve, got %v", ip)
	}
}

// ─── Local API tests ─────────────────────────────────────────────────────────

func TestLocalStatus(t *testing.T) {
	e := testEngine(t)
	e.nodeID = "test-node-123"
	e.virtualIP = net.ParseIP("100.64.0.1")

	status := e.LocalStatus()
	if status["nodeId"] != "test-node-123" {
		t.Errorf("nodeId: got %v, want test-node-123", status["nodeId"])
	}
	if status["virtualIp"] != "100.64.0.1" {
		t.Errorf("virtualIp: got %v, want 100.64.0.1", status["virtualIp"])
	}
}

func TestHandleAPIStatus(t *testing.T) {
	e := testEngine(t)
	e.nodeID = "test-node-456"
	e.virtualIP = net.ParseIP("100.64.0.5")

	w := httptest.NewRecorder()
	e.handleAPIStatus(w, httptest.NewRequest(http.MethodGet, "/status", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status code: got %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["nodeId"] != "test-node-456" {
		t.Errorf("nodeId: got %v, want test-node-456", resp["nodeId"])
	}
}

func TestHandleAPIMetrics(t *testing.T) {
	e := testEngine(t)
	e.metricPacketsTx.Add(42)
	e.metricPacketsRx.Add(10)
	e.metricBytesTx.Add(1024)
	e.metricBytesRx.Add(512)

	w := httptest.NewRecorder()
	e.handleAPIMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status code: got %d, want %d", w.Code, http.StatusOK)
	}

	body := w.Body.String()
	if !containsStr(body, "karadul_packets_tx_total 42") {
		t.Errorf("expected packets_tx 42 in metrics output, got:\n%s", body)
	}
	if !containsStr(body, "karadul_bytes_rx_total 512") {
		t.Errorf("expected bytes_rx 512 in metrics output, got:\n%s", body)
	}
}

// ─── Packet helpers ──────────────────────────────────────────────────────────

func TestPacketDstPort(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want uint16
	}{
		{
			name: "tcp packet port 80",
			pkt: func() []byte {
				pkt := make([]byte, 24)
				pkt[0] = 0x45 // IPv4, 20-byte header
				pkt[9] = 6    // protocol = TCP
				pkt[22] = 0   // dst port high byte
				pkt[23] = 80  // dst port low byte
				return pkt
			}(),
			want: 80,
		},
		{
			name: "udp packet port 53",
			pkt: func() []byte {
				pkt := make([]byte, 28)
				pkt[0] = 0x45 // IPv4, 20-byte header
				pkt[9] = 17   // protocol = UDP
				pkt[22] = 0   // dst port high byte
				pkt[23] = 53  // dst port low byte
				return pkt
			}(),
			want: 53,
		},
		{
			name: "too short",
			pkt: func() []byte {
				pkt := make([]byte, 10)
				pkt[0] = 0x45
				return pkt
			}(),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packetDstPort(tt.pkt)
			if got != tt.want {
				t.Errorf("packetDstPort() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ─── ID counter tests ────────────────────────────────────────────────────────

func TestNextID(t *testing.T) {
	e := testEngine(t)

	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := e.nextID()
		if ids[id] {
			t.Errorf("duplicate ID: %d", id)
		}
		ids[id] = true
	}
}

// ─── Public endpoint tests ───────────────────────────────────────────────────

func TestPublicEP_Atomic(t *testing.T) {
	e := testEngine(t)

	if ep := e.publicEP.Load(); ep != nil {
		t.Errorf("initial publicEP should be nil, got %v", ep)
	}

	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}
	e.publicEP.Store(addr)

	loaded := e.publicEP.Load()
	if loaded == nil || !loaded.IP.Equal(net.ParseIP("203.0.113.1")) || loaded.Port != 12345 {
		t.Errorf("publicEP: got %v, want 203.0.113.1:12345", loaded)
	}
}

// ─── Sign request tests ──────────────────────────────────────────────────────

func TestSignRequest(t *testing.T) {
	e := testEngine(t)

	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequest(http.MethodPost, "/api/v1/poll", nil)
	if err != nil {
		t.Fatal(err)
	}

	e.signRequest(req, body)

	keyHeader := req.Header.Get("X-Karadul-Key")
	sigHeader := req.Header.Get("X-Karadul-Sig")

	if keyHeader == "" {
		t.Error("expected non-empty X-Karadul-Key header")
	}
	if sigHeader == "" {
		t.Error("expected non-empty X-Karadul-Sig header")
	}

	decoded, err := base64.StdEncoding.DecodeString(keyHeader)
	if err != nil {
		t.Fatalf("decode key header: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("key header decoded length: got %d, want 32", len(decoded))
	}
}

// ─── Helper ──────────────────────────────────────────────────────────────────

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

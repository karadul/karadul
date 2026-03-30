package mesh

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/coordinator"
	klog "github.com/karadul/karadul/internal/log"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	m := NewManager(log, nil)
	t.Cleanup(func() { m.Stop() })
	return m
}

func newTestLogger() *klog.Logger {
	return klog.New(nil, klog.LevelError, klog.FormatText)
}

// encodeKey returns the base64 encoding of a [32]byte key (matching keyFromBase64).
func encodeKey(k [32]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// TestKeyFromBase64_RoundTrip verifies that keyFromBase64(encodeKey(k)) == k.
func TestKeyFromBase64_RoundTrip(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i)
	}
	got, err := keyFromBase64(encodeKey(k))
	if err != nil {
		t.Fatalf("keyFromBase64: %v", err)
	}
	if got != k {
		t.Fatalf("round-trip mismatch: got %x, want %x", got, k)
	}
}

// TestKeyFromBase64_Invalid verifies that invalid base64 returns an error.
func TestKeyFromBase64_Invalid(t *testing.T) {
	if _, err := keyFromBase64("not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// TestKeyFromBase64_WrongLen verifies that a valid base64 with wrong decoded length errors.
func TestKeyFromBase64_WrongLen(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	if _, err := keyFromBase64(short); err == nil {
		t.Fatal("expected error for wrong key length")
	}
	// Error message
	if err := (&keyLenError{n: 8}).Error(); err == "" {
		t.Fatal("keyLenError.Error() should return non-empty string")
	}
}

// TestKeyFromBase64_Whitespace verifies that leading/trailing whitespace is trimmed.
func TestKeyFromBase64_Whitespace(t *testing.T) {
	var k [32]byte
	k[0] = 0xAB
	encoded := "  " + encodeKey(k) + "\n"
	got, err := keyFromBase64(encoded)
	if err != nil {
		t.Fatalf("keyFromBase64 with whitespace: %v", err)
	}
	if got != k {
		t.Fatalf("whitespace trimming failed: got %x", got)
	}
}

// TestNewTopologyManager verifies the constructor returns a non-nil manager.
func TestNewTopologyManager(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())
	if tm == nil {
		t.Fatal("NewTopologyManager returned nil")
	}
}

// TestTopologyManager_Apply_AddsPeers verifies that Apply adds active nodes as peers.
func TestTopologyManager_Apply_AddsPeers(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	selfKey[0] = 0xFF
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	var peerKey [32]byte
	peerKey[0] = 0x01

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "node-1",
				PublicKey: encodeKey(peerKey),
				Hostname:  "peer1",
				VirtualIP: "100.64.0.2",
				Endpoint:  "1.2.3.4:51820",
				Status:    coordinator.NodeStatusActive,
			},
		},
	}
	tm.Apply(state)

	peers := m.ListPeers()
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].Hostname != "peer1" {
		t.Errorf("hostname: want peer1, got %s", peers[0].Hostname)
	}
	if peers[0].VirtualIP.String() != "100.64.0.2" {
		t.Errorf("vip: want 100.64.0.2, got %s", peers[0].VirtualIP)
	}
}

// TestTopologyManager_Apply_SkipsSelf verifies that our own node is not added as a peer.
func TestTopologyManager_Apply_SkipsSelf(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	selfKey[0] = 0xAA
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "self",
				PublicKey: encodeKey(selfKey),
				Hostname:  "self-node",
				VirtualIP: "100.64.0.1",
				Status:    coordinator.NodeStatusActive,
			},
		},
	}
	tm.Apply(state)

	if len(m.ListPeers()) != 0 {
		t.Fatal("self node should not be added as a peer")
	}
}

// TestTopologyManager_Apply_SkipsInactive verifies that non-active nodes are skipped.
func TestTopologyManager_Apply_SkipsInactive(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	var peerKey [32]byte
	peerKey[0] = 0x02

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "node-pending",
				PublicKey: encodeKey(peerKey),
				Hostname:  "pending-node",
				VirtualIP: "100.64.0.3",
				Status:    coordinator.NodeStatusPending,
			},
		},
	}
	tm.Apply(state)

	if len(m.ListPeers()) != 0 {
		t.Fatal("pending node should not be added as a peer")
	}
}

// TestTopologyManager_Apply_SkipsBadKey verifies that nodes with invalid public keys are skipped.
func TestTopologyManager_Apply_SkipsBadKey(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "bad-key",
				PublicKey: "this-is-not-valid-base64!!!",
				Hostname:  "bad",
				VirtualIP: "100.64.0.4",
				Status:    coordinator.NodeStatusActive,
			},
		},
	}
	tm.Apply(state)

	if len(m.ListPeers()) != 0 {
		t.Fatal("node with bad key should not be added")
	}
}

// TestTopologyManager_Apply_SkipsBadVIP verifies that nodes with invalid VIPs are skipped.
func TestTopologyManager_Apply_SkipsBadVIP(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	var peerKey [32]byte
	peerKey[0] = 0x03

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "bad-vip",
				PublicKey: encodeKey(peerKey),
				Hostname:  "badvip",
				VirtualIP: "not-an-ip",
				Status:    coordinator.NodeStatusActive,
			},
		},
	}
	tm.Apply(state)

	if len(m.ListPeers()) != 0 {
		t.Fatal("node with bad VIP should not be added")
	}
}

// TestTopologyManager_Apply_ExpiresRemovedPeers verifies that peers absent from an
// updated topology are transitioned to PeerExpired.
func TestTopologyManager_Apply_ExpiresRemovedPeers(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	var peerKey1 [32]byte
	peerKey1[0] = 0x11
	var peerKey2 [32]byte
	peerKey2[0] = 0x22

	// First apply: two peers.
	state1 := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{ID: "n1", PublicKey: encodeKey(peerKey1), Hostname: "p1", VirtualIP: "100.64.0.10", Status: "online"},
			{ID: "n2", PublicKey: encodeKey(peerKey2), Hostname: "p2", VirtualIP: "100.64.0.11", Status: "online"},
		},
	}
	tm.Apply(state1)

	if len(m.ListPeers()) != 2 {
		t.Fatalf("expected 2 peers after first apply, got %d", len(m.ListPeers()))
	}

	// Second apply: only first peer.
	state2 := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{ID: "n1", PublicKey: encodeKey(peerKey1), Hostname: "p1", VirtualIP: "100.64.0.10", Status: "online"},
		},
	}
	tm.Apply(state2)

	p2, ok := m.GetPeer(peerKey2)
	if !ok {
		t.Fatal("peer2 should still be in manager (as expired)")
	}
	if p2.GetState() != PeerExpired {
		t.Errorf("peer2 should be expired after removal, got %s", p2.GetState())
	}
}

// TestTopologyManager_Apply_WithRoutes verifies that routes are parsed from the node entry.
func TestTopologyManager_Apply_WithRoutes(t *testing.T) {
	m := newTestManager(t)
	var selfKey [32]byte
	tm := NewTopologyManager(m, selfKey, newTestLogger())

	var peerKey [32]byte
	peerKey[0] = 0x44

	state := coordinator.NetworkState{
		Nodes: []*coordinator.Node{
			{
				ID:        "n-routes",
				PublicKey: encodeKey(peerKey),
				Hostname:  "router",
				VirtualIP: "100.64.0.20",
				Status:    coordinator.NodeStatusActive,
				Routes:    []string{"192.168.0.0/24", "10.0.0.0/8"},
			},
		},
	}
	tm.Apply(state)

	p, ok := m.GetPeer(peerKey)
	if !ok {
		t.Fatal("peer not found")
	}
	p.mu.RLock()
	nRoutes := len(p.Routes)
	p.mu.RUnlock()
	if nRoutes != 2 {
		t.Errorf("expected 2 routes, got %d", nRoutes)
	}
}

// TestManager_Remove verifies that Remove transitions a peer to PeerExpired.
func TestManager_Remove(t *testing.T) {
	m := newTestManager(t)

	var key [32]byte
	key[0] = 0x55
	vip := net.ParseIP("100.64.0.30")
	m.AddOrUpdate(key, "removetest", "node-r", vip, "", nil)

	p, ok := m.GetPeer(key)
	if !ok {
		t.Fatal("peer not found after AddOrUpdate")
	}

	m.Remove(key)

	if p.GetState() != PeerExpired {
		t.Errorf("Remove should set peer to expired, got %s", p.GetState())
	}
}

// TestManager_Remove_Unknown verifies that removing a nonexistent key is a no-op.
func TestManager_Remove_Unknown(t *testing.T) {
	m := newTestManager(t)
	var unknown [32]byte
	unknown[0] = 0xEE
	// Should not panic.
	m.Remove(unknown)
}

// TestPeerSummary verifies that PeerSummary returns a non-empty string.
func TestPeerSummary(t *testing.T) {
	var key [32]byte
	p := NewPeer(key, "mynode", "node-id-12345678", net.ParseIP("100.64.0.50"))
	s := PeerSummary(p)
	if s == "" {
		t.Fatal("PeerSummary should return non-empty string")
	}
	// Should contain hostname and state.
	if len(s) < 10 {
		t.Errorf("PeerSummary too short: %q", s)
	}
}

// TestPeerSummary_WithEndpoint verifies PeerSummary with a non-nil endpoint.
func TestPeerSummary_WithEndpoint(t *testing.T) {
	var key [32]byte
	p := NewPeer(key, "epnode", "node-id-ABCDEFGH", net.ParseIP("100.64.0.51"))
	p.SetEndpoint(&net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 51820})
	s := PeerSummary(p)
	if s == "" {
		t.Fatal("PeerSummary should return non-empty string")
	}
}

// TestPeer_IsExpired verifies IsExpired for explicitly expired and timed-out peers.
func TestPeer_IsExpired(t *testing.T) {
	var key [32]byte

	// Explicitly expired.
	p1 := NewPeer(key, "exp", "id-exp", net.ParseIP("100.64.0.60"))
	p1.Transition(PeerExpired)
	if !p1.IsExpired() {
		t.Error("peer in PeerExpired state should report IsExpired=true")
	}

	// Not expired.
	p2 := NewPeer(key, "fresh", "id-fresh", net.ParseIP("100.64.0.61"))
	p2.Transition(PeerDirect)
	if p2.IsExpired() {
		t.Error("recently-created direct peer should not be expired")
	}

	// Timed out by lastSeen.
	p3 := NewPeer(key, "old", "id-old", net.ParseIP("100.64.0.62"))
	p3.mu.Lock()
	p3.lastSeen = p3.lastSeen.Add(-11 * time.Minute)
	p3.mu.Unlock()
	if !p3.IsExpired() {
		t.Error("peer not seen for >10 min should be expired")
	}
}

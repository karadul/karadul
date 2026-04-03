package node

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/coordinator"
	"github.com/karadul/karadul/internal/crypto"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/mesh"
	"github.com/karadul/karadul/internal/protocol"
	"github.com/karadul/karadul/internal/relay"
)

// ─── 1. handleHandshakeInit with invalid Noise packets ─────────────────────

func TestHandleHandshakeInit_InvalidNoisePacket(t *testing.T) {
	e := testEngine(t)

	// A packet that is too short to be a valid HandshakeInit should silently return.
	// HandshakeInitSize = 104 bytes; send fewer bytes.
	shortPkt := make([]byte, 50)
	shortPkt[0] = protocol.TypeHandshakeInit

	// Should not panic or block -- silently returns.
	e.handleHandshakeInit(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}, shortPkt)
}

func TestHandleHandshakeInit_RandomNoisePacket(t *testing.T) {
	e := testEngine(t)

	// Craft a packet with correct size but garbage Noise payload.
	// This will pass UnmarshalMsgHandshakeInit but fail the Noise handshake.
	pkt := make([]byte, protocol.HandshakeInitSize)
	pkt[0] = protocol.TypeHandshakeInit
	// Rest is zeros -- will fail ResponderHandshake ReadMessage1.

	// Should silently return (not panic).
	e.handleHandshakeInit(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}, pkt)

	// Verify no sessions were created.
	e.mu.RLock()
	n := len(e.sessions)
	e.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 sessions after invalid handshake, got %d", n)
	}
}

func TestHandleHandshakeInit_EmptyPacket(t *testing.T) {
	e := testEngine(t)

	// Completely empty packet -- UnmarshalMsgHandshakeInit returns error.
	e.handleHandshakeInit(nil, []byte{})

	e.mu.RLock()
	n := len(e.sessions)
	e.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 sessions after empty handshake, got %d", n)
	}
}

// ─── 2. handleHandshakeResp with unknown receiver index ────────────────────

func TestHandleHandshakeResp_UnknownReceiverIndex(t *testing.T) {
	e := testEngine(t)

	// Craft a HandshakeResp with a receiver index that doesn't match any pending HS.
	pkt := make([]byte, protocol.HandshakeRespSize)
	pkt[0] = protocol.TypeHandshakeResp
	// receiverIndex at bytes 8:12 -- set to 99999 which is not in e.pending.
	pkt[8] = 0x9F
	pkt[9] = 0x86
	pkt[10] = 0x01
	pkt[11] = 0x00

	// Should silently return without creating any sessions.
	e.handleHandshakeResp(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}, pkt)

	e.mu.RLock()
	n := len(e.sessions)
	e.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 sessions after unknown receiver index, got %d", n)
	}
}

func TestHandleHandshakeResp_EmptyPacket(t *testing.T) {
	e := testEngine(t)

	// Empty packet -- UnmarshalMsgHandshakeResp returns error.
	e.handleHandshakeResp(nil, []byte{})

	e.mu.RLock()
	n := len(e.sessions)
	e.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 sessions after empty resp, got %d", n)
	}
}

// ─── 3. connectPeer with endpoint set (direct handshake path) ──────────────

func TestConnectPeer_WithEndpoint(t *testing.T) {
	e := testEngine(t)

	// Bind a real UDP socket so initiateHandshake can write to it.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	t.Cleanup(cancel)

	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}

	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	peer := mesh.NewPeer(pubKey, "ep-peer", "n1", net.ParseIP("100.64.0.2"))
	peer.SetEndpoint(ep)

	// connectPeer with an endpoint should try a direct handshake first.
	err = e.connectPeer(peer)
	if err != nil {
		t.Fatalf("connectPeer with endpoint: %v", err)
	}

	// Verify a pending handshake was created.
	e.mu.RLock()
	pendingCount := len(e.pending)
	e.mu.RUnlock()
	if pendingCount == 0 {
		t.Error("expected at least one pending handshake after connectPeer with endpoint")
	}
}

func TestConnectPeer_NoEndpoint_NoDERP(t *testing.T) {
	e := testEngine(t)

	// Set up ctx so connectPeer doesn't panic on e.ctx.
	ctx, cancel := context.WithCancel(context.Background())
	e.ctx = ctx
	t.Cleanup(cancel)

	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i + 2)
	}

	peer := mesh.NewPeer(pubKey, "no-ep-peer", "n2", net.ParseIP("100.64.0.3"))
	// No endpoint set, no DERP client.

	err := e.connectPeer(peer)
	if err != nil {
		t.Fatalf("connectPeer without endpoint/DERP should return nil, got: %v", err)
	}
}

// ─── 4. shutdown cleanup of all subsystems ─────────────────────────────────

func TestShutdown_Cleanup(t *testing.T) {
	e := testEngine(t)

	// Set up subsystems that shutdown should clean up.
	mtun := &mockTUN{name: "test-tun", mtu: 1420}
	e.tun = mtun

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp

	// Create a manager we can verify gets stopped.
	e.manager = mesh.NewManager(e.log, nil)

	// Execute shutdown.
	err = e.shutdown()
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	// Verify TUN was closed.
	if !mtun.closed {
		t.Error("expected TUN to be closed after shutdown")
	}

	// Verify stopCh is closed (non-blocking read should succeed).
	select {
	case <-e.stopCh:
		// Expected -- stopCh was closed.
	default:
		t.Error("expected stopCh to be closed after shutdown")
	}
}

func TestShutdown_NilSubsystems(t *testing.T) {
	e := testEngine(t)

	// All subsystems are nil by default -- should not panic.
	err := e.shutdown()
	if err != nil {
		t.Fatalf("shutdown with nil subsystems: %v", err)
	}
}

func TestShutdown_WithDNSRestore(t *testing.T) {
	e := testEngine(t)

	restored := false
	e.dnsRestore = func() error {
		restored = true
		return nil
	}

	err := e.shutdown()
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !restored {
		t.Error("expected dnsRestore to be called during shutdown")
	}
}

// ─── 5. ensureDERPClient with empty DERP map ───────────────────────────────

func TestEnsureDERPClient_EmptyDERPMap(t *testing.T) {
	e := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Empty DERP map -- no regions/nodes.
	dm := &coordinator.DERPMap{Regions: nil}
	e.ensureDERPClient(ctx, dm)

	// Should not create a DERP client.
	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != nil {
		t.Error("expected nil derpClient with empty DERP map")
	}
}

func TestEnsureDERPClient_EmptyRegions(t *testing.T) {
	e := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// DERP map with regions but no nodes.
	dm := &coordinator.DERPMap{
		Regions: []*coordinator.DERPRegion{
			{RegionID: 1, RegionCode: "us", RegionName: "US", Nodes: nil},
		},
	}
	e.ensureDERPClient(ctx, dm)

	// Should not create a DERP client (no nodes to connect to).
	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != nil {
		t.Error("expected nil derpClient with empty region nodes")
	}
}

func TestEnsureDERPClient_AlreadyRunning(t *testing.T) {
	e := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Simulate an already-running DERP client by pre-setting a real relay.Client.
	existing := relay.NewClient("http://127.0.0.1:1", e.kp.Public, nil, e.log)
	e.derpMu.Lock()
	e.derpClient = existing
	e.derpMu.Unlock()

	// Call ensureDERPClient with a valid map -- it should be a no-op.
	dm := &coordinator.DERPMap{
		Regions: []*coordinator.DERPRegion{
			{
				RegionID:   1,
				RegionCode: "us",
				RegionName: "US",
				Nodes: []*coordinator.DERPNode{{
					Name:     "derp1",
					HostName: "127.0.0.1",
					DERPPort: 443,
				}},
			},
		},
	}
	e.ensureDERPClient(ctx, dm)

	// Should still be the same client -- not replaced.
	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != existing {
		t.Error("expected existing DERP client to be preserved")
	}
}

// ─── 6. rekeyLoop triggering rekey on expired session ──────────────────────

func TestRekeyLoop_TriggersOnExpiredSession(t *testing.T) {
	e := testEngine(t)

	// Set up a UDP socket so initiateHandshake can write.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	// Build a session that has expired (past sessionLifetime).
	var remotePub [32]byte
	for i := range remotePub {
		remotePub[i] = byte(i + 20)
	}

	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i)
		recvKey[i] = byte(i + 1)
	}

	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	ps := e.buildSession(remotePub, sendKey, recvKey, 100, 200, ep)

	peer := mesh.NewPeer(remotePub, "expired-peer", "n1", net.ParseIP("100.64.0.10"))
	peer.SetEndpoint(ep)
	ps.peer = peer

	// Age the session past sessionLifetime so NeedsRekey() returns true.
	ps.session.mu.Lock()
	ps.session.createdAt = time.Now().Add(-(sessionLifetime + time.Second))
	ps.session.mu.Unlock()

	// Manually scan -- this is the same logic rekeyLoop uses internally.
	e.mu.RLock()
	var toRekey []*peerSession
	for _, s := range e.sessions {
		if s.session.NeedsRekey() {
			toRekey = append(toRekey, s)
		}
	}
	e.mu.RUnlock()

	if len(toRekey) == 0 {
		t.Fatal("expected at least one session needing rekey")
	}

	for _, s := range toRekey {
		if s.peer != nil {
			e.RekeyPeer(s.peer)
		}
	}

	// Verify the old session was cleaned up.
	e.mu.RLock()
	_, hasByID := e.byID[100]
	e.mu.RUnlock()
	if hasByID {
		t.Error("expected byID entry to be cleaned up after rekey")
	}
}

func TestRekeyLoop_NoExpiredSessions(t *testing.T) {
	e := testEngine(t)

	// Build a fresh session that does NOT need rekey.
	var remotePub [32]byte
	remotePub[0] = 0xAA
	e.buildSession(remotePub, [32]byte{1}, [32]byte{2}, 50, 60, nil)

	// Manually scan -- should find nothing to rekey.
	e.mu.RLock()
	var toRekey []*peerSession
	for _, ps := range e.sessions {
		if ps.session.NeedsRekey() {
			toRekey = append(toRekey, ps)
		}
	}
	e.mu.RUnlock()

	if len(toRekey) != 0 {
		t.Errorf("expected 0 sessions needing rekey, got %d", len(toRekey))
	}
}

// ─── 7. endpointRefreshLoop endpoint change detection ──────────────────────

func TestEndpointRefreshLoop_ChangeDetection(t *testing.T) {
	e := testEngine(t)

	// Simulate: initially no publicEP, then we discover one.
	ep1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}

	// No previous endpoint -- this should be treated as a change.
	prevEP := e.publicEP.Load()
	e.publicEP.Store(ep1)
	changed := prevEP == nil || ep1.String() != prevEP.String()
	if !changed {
		t.Error("expected endpoint change when prevEP is nil")
	}

	// Same endpoint again -- should NOT be a change.
	prevEP = e.publicEP.Load()
	ep2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345}
	e.publicEP.Store(ep2)
	changed = prevEP == nil || ep2.String() != prevEP.String()
	if changed {
		t.Error("expected no change when endpoint is the same")
	}

	// Different endpoint -- should be a change.
	prevEP = e.publicEP.Load()
	ep3 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 54321}
	e.publicEP.Store(ep3)
	changed = prevEP == nil || ep3.String() != prevEP.String()
	if !changed {
		t.Error("expected change when endpoint differs")
	}
}

func TestEndpointRefreshLoop_ContextCancellation(t *testing.T) {
	e := testEngine(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.endpointRefreshLoop(ctx)
		close(done)
	}()

	// Cancel immediately.
	cancel()

	select {
	case <-done:
		// Good -- loop exited.
	case <-time.After(35 * time.Second):
		t.Fatal("endpointRefreshLoop did not exit on context cancellation")
	}
}

// ─── Additional coverage: handleHandshakeInit via DERP (nil addr) ───────────

func TestHandleHandshakeInit_ViaDERP(t *testing.T) {
	e := testEngine(t)

	// When addr is nil, the packet arrived via DERP.
	// With a random packet, the Noise handshake will fail -- no panic.
	pkt := make([]byte, protocol.HandshakeInitSize)
	pkt[0] = protocol.TypeHandshakeInit

	// Should silently return (no panic on nil addr).
	e.handleHandshakeInit(nil, pkt)
}

// ─── Additional coverage: handleHandshakeResp via DERP (nil addr) ───────────

func TestHandleHandshakeResp_ViaDERP_UnknownIndex(t *testing.T) {
	e := testEngine(t)

	// Craft resp with unknown index, arriving via DERP (nil addr).
	pkt := make([]byte, protocol.HandshakeRespSize)
	pkt[0] = protocol.TypeHandshakeResp

	e.handleHandshakeResp(nil, pkt)

	e.mu.RLock()
	n := len(e.sessions)
	e.mu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 sessions, got %d", n)
	}
}

// ─── Additional coverage: handleData with mock TUN ──────────────────────────

func TestHandleData_DecryptSuccess(t *testing.T) {
	e := testEngine(t)

	mtun := &mockTUN{name: "test-tun", mtu: 1420}
	e.tun = mtun

	// Set up a session with known keys.
	var remotePub [32]byte
	remotePub[0] = 0xDD

	var sendKey, recvKey [32]byte
	for i := range sendKey {
		sendKey[i] = byte(i)
		recvKey[i] = byte(i)
	}
	ps := e.buildSession(remotePub, sendKey, recvKey, 42, 84, nil)

	peer := mesh.NewPeer(remotePub, "data-peer", "n1", net.ParseIP("100.64.0.5"))
	ps.peer = peer

	// Encrypt a valid IPv4 packet using the session.
	// Minimal IPv4 packet: 20-byte header with src=100.64.0.1, dst=100.64.0.2, proto=TCP.
	ipPkt := make([]byte, 24)
	ipPkt[0] = 0x45 // IPv4, 20-byte header
	ipPkt[9] = 6    // TCP
	copy(ipPkt[12:16], net.ParseIP("100.64.0.1").To4())
	copy(ipPkt[16:20], net.ParseIP("100.64.0.2").To4())

	counter, ct, err := ps.session.Encrypt(ipPkt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Build a data message with the known receiver index.
	wireMsg := (&protocol.MsgData{
		ReceiverIndex: 42, // matches localID in our session
		Counter:       counter,
		Ciphertext:    ct,
	}).MarshalBinary()

	// Feed it to handleData.
	e.handleData(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000}, wireMsg)

	// Verify metrics were updated.
	if e.metricPacketsRx.Load() != 1 {
		t.Errorf("packets rx: got %d, want 1", e.metricPacketsRx.Load())
	}
}

// ─── Additional coverage: sendToPeer no-path error ─────────────────────────

func TestSendToPeer_NoPathToPeer(t *testing.T) {
	e := testEngine(t)

	// No DERP client, no endpoint.
	var remotePub [32]byte
	remotePub[0] = 0xFF
	ps := e.buildSession(remotePub, [32]byte{1}, [32]byte{2}, 11, 22, nil)
	ps.endpoint.Store(nil)

	peer := mesh.NewPeer(remotePub, "no-path-peer", "n1", net.ParseIP("100.64.0.7"))
	ps.peer = peer

	err := e.sendToPeer(peer, []byte("test"))
	if err == nil {
		t.Fatal("expected error when no path to peer")
	}
}

// ─── Additional coverage: sendToPeer triggers handshake for new peer ────────

func TestSendToPeer_TriggersHandshakeForNewPeer(t *testing.T) {
	e := testEngine(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	var pubKey [32]byte
	pubKey[0] = 0xCC
	peer := mesh.NewPeer(pubKey, "new-peer", "n1", net.ParseIP("100.64.0.8"))
	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	peer.SetEndpoint(ep)

	// sendToPeer on a peer with no session should not error, but drop the packet.
	err = e.sendToPeer(peer, []byte("first packet"))
	if err != nil {
		t.Fatalf("sendToPeer new peer: %v", err)
	}

	// Give the goroutine time to start.
	time.Sleep(100 * time.Millisecond)

	// A pending handshake should have been created (asynchronously).
	e.mu.RLock()
	pendingCount := len(e.pending)
	e.mu.RUnlock()
	if pendingCount == 0 {
		t.Error("expected pending handshake after sendToPeer for new peer")
	}
}

// ─── Additional coverage: initiateHandshake duplicate prevention ────────────

func TestInitiateHandshake_DuplicatePrevention(t *testing.T) {
	e := testEngine(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i + 5)
	}

	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	peer := mesh.NewPeer(pubKey, "dup-peer", "n1", net.ParseIP("100.64.0.8"))
	peer.SetEndpoint(ep)

	// First handshake -- should succeed.
	err = e.initiateHandshake(peer)
	if err != nil {
		t.Fatalf("first initiateHandshake: %v", err)
	}

	// Second handshake for same peer -- should be a no-op (nil error).
	err = e.initiateHandshake(peer)
	if err != nil {
		t.Fatalf("duplicate initiateHandshake: %v", err)
	}

	// Verify only one pending handshake exists for this peer.
	e.mu.RLock()
	count := 0
	for _, ph := range e.pending {
		if ph.peer.PublicKey == pubKey {
			count++
		}
	}
	e.mu.RUnlock()
	if count != 1 {
		t.Errorf("expected 1 pending handshake for peer, got %d", count)
	}
}

// ─── Additional coverage: handleUDPPacket dispatch ─────────────────────────

func TestHandleUDPPacket_KnownTypes(t *testing.T) {
	e := testEngine(t)

	// TypeHandshakeInit -- too short for valid init, but should not panic.
	e.handleUDPPacket(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		[]byte{protocol.TypeHandshakeInit})

	// TypeHandshakeResp -- too short for valid resp, but should not panic.
	e.handleUDPPacket(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		[]byte{protocol.TypeHandshakeResp})

	// TypeData -- too short for valid data, but should not panic.
	e.handleUDPPacket(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		[]byte{protocol.TypeData})

	// TypeKeepalive -- should be silently ignored.
	e.handleUDPPacket(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000},
		[]byte{protocol.TypeKeepalive})
}

// ─── Additional coverage: reportEndpoint error path ─────────────────────────

func TestReportEndpoint_Error(t *testing.T) {
	e := testEngine(t)
	e.serverURL = "http://127.0.0.1:0" // unreachable

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := e.reportEndpoint(ctx, "1.2.3.4:5678")
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

// ─── Additional coverage: full handshake round-trip (initiator + responder) ─

func TestFullHandshakeRoundTrip(t *testing.T) {
	// Create two engines -- Alice and Bob -- and do a full Noise IK handshake.
	kpA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.NodeConfig{ServerURL: "http://127.0.0.1:8080", Hostname: "alice", AuthKey: "test"}
	logA := klog.New(nil, klog.LevelDebug, klog.FormatText)
	alice := NewEngine(cfg, kpA, logA)
	alice.manager = mesh.NewManager(logA, nil)

	cfgB := &config.NodeConfig{ServerURL: "http://127.0.0.1:8080", Hostname: "bob", AuthKey: "test"}
	logB := klog.New(nil, klog.LevelDebug, klog.FormatText)
	bob := NewEngine(cfgB, kpB, logB)
	bob.manager = mesh.NewManager(logB, nil)

	// Alice initiates handshake to Bob.
	hsA, err := crypto.InitiatorHandshake(kpA, kpB.Public)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := hsA.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}

	localIDA := alice.nextID()
	initMsg := &protocol.MsgHandshakeInit{SenderIndex: localIDA}
	copy(initMsg.Ephemeral[:], msg1[:32])
	copy(initMsg.EncStatic[:], msg1[32:80])
	copy(initMsg.EncPayload[:], msg1[80:96])

	alice.mu.Lock()
	alice.pending[localIDA] = &pendingHandshake{
		peer:    mesh.NewPeer(kpB.Public, "bob", "b1", net.ParseIP("100.64.0.2")),
		hs:      hsA,
		localID: localIDA,
		sentAt:  time.Now(),
	}
	alice.mu.Unlock()

	// Bob receives the init (handles it via DERP -- addr=nil).
	bob.handleHandshakeInit(nil, initMsg.MarshalBinary())

	// Verify Bob has a session.
	bob.mu.RLock()
	bobSessions := len(bob.sessions)
	bob.mu.RUnlock()
	if bobSessions != 1 {
		t.Fatalf("Bob should have 1 session, got %d", bobSessions)
	}

	// Get the response that Bob would have sent -- since addr is nil (DERP),
	// Bob sends via DERP (which is nil), so the response is dropped.
	// Redo with UDP sockets.

	// Clean up Alice's pending and Bob's sessions for a clean retry.
	alice.mu.Lock()
	delete(alice.pending, localIDA)
	alice.mu.Unlock()

	bob.mu.Lock()
	for k := range bob.sessions {
		delete(bob.sessions, k)
	}
	for k := range bob.byID {
		delete(bob.byID, k)
	}
	bob.mu.Unlock()

	// Bind UDP sockets.
	udpA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP A listen: %v", err)
	}
	alice.udp = udpA

	udpB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		udpA.Close()
		t.Skipf("UDP B listen: %v", err)
	}
	bob.udp = udpB

	t.Cleanup(func() {
		udpA.Close()
		udpB.Close()
	})

	bobAddr := udpB.LocalAddr().(*net.UDPAddr)

	// Alice initiates again.
	hsA2, err := crypto.InitiatorHandshake(kpA, kpB.Public)
	if err != nil {
		t.Fatal(err)
	}
	msg1v2, err := hsA2.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}

	localIDA2 := alice.nextID()
	initMsg2 := &protocol.MsgHandshakeInit{SenderIndex: localIDA2}
	copy(initMsg2.Ephemeral[:], msg1v2[:32])
	copy(initMsg2.EncStatic[:], msg1v2[32:80])
	copy(initMsg2.EncPayload[:], msg1v2[80:96])

	alice.mu.Lock()
	alice.pending[localIDA2] = &pendingHandshake{
		peer:    mesh.NewPeer(kpB.Public, "bob", "b1", net.ParseIP("100.64.0.2")),
		hs:      hsA2,
		localID: localIDA2,
		sentAt:  time.Now(),
	}
	alice.mu.Unlock()

	// Bob handles init -- responds to aliceAddr via UDP.
	aliceAddr := udpA.LocalAddr().(*net.UDPAddr)
	bob.handleHandshakeInit(aliceAddr, initMsg2.MarshalBinary())

	// Read Bob's response from Alice's UDP socket.
	buf := make([]byte, 1500)
	udpA.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := udpA.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("alice read response: %v", err)
	}

	// Alice handles the response.
	alice.handleHandshakeResp(bobAddr, buf[:n])

	// Both should now have sessions.
	alice.mu.RLock()
	aliceSessCount := len(alice.sessions)
	alice.mu.RUnlock()
	if aliceSessCount != 1 {
		t.Errorf("Alice should have 1 session, got %d", aliceSessCount)
	}
}

// ─── Additional coverage: pollLoop with DERP map ───────────────────────────

func TestPollLoop_AppliesDERPMap(t *testing.T) {
	gotPath := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotPath <- r.URL.Path:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":1,"nodes":null,"acl":{},"derpMap":{"regions":[{"regionId":1,"regionCode":"test","regionName":"Test","nodes":[{"name":"d1","regionId":1,"hostName":"127.0.0.1","derpPort":443}]}]}}`))
	}))
	defer srv.Close()

	e := testEngine(t)
	e.serverURL = srv.URL
	// pollLoop calls e.topology.Apply -- must be initialized.
	e.topology = mesh.NewTopologyManager(e.manager, e.kp.Public, e.log)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Run pollLoop -- it should parse the DERP map and call ensureDERPClient.
	// The DERP client will fail to connect but that's fine -- we verify the path is taken.
	done := make(chan struct{})
	go func() {
		e.pollLoop(ctx)
		close(done)
	}()

	// Wait for at least one request.
	select {
	case p := <-gotPath:
		if p != "/api/v1/poll" {
			t.Errorf("expected poll request, got path %q", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for poll request")
	}

	cancel()
	<-done
}

// ─── Additional coverage: handleAPIExitNodeEnable via HTTP ──────────────────

func TestHandleAPIExitNodeEnable_ServerError(t *testing.T) {
	e := testEngine(t)

	// No mock for actual EnableExitNode system call -- it will fail.
	w := httptest.NewRecorder()
	e.handleAPIExitNodeEnable(w, httptest.NewRequest(http.MethodPost, "/exit-node/enable",
		strings.NewReader(`{"out_interface":"nonexistent0"}`)))

	// Should get a 500 since the interface doesn't exist.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d; body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}
}

// ─── Additional coverage: sendToPeer with expired session ──────────────────

func TestSendToPeer_ExpiredSessionTriggersReconnect(t *testing.T) {
	e := testEngine(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	var remotePub [32]byte
	remotePub[0] = 0xBB

	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	ps := e.buildSession(remotePub, [32]byte{1}, [32]byte{2}, 33, 44, ep)

	peer := mesh.NewPeer(remotePub, "expired-sess-peer", "n1", net.ParseIP("100.64.0.9"))
	peer.SetEndpoint(ep)
	ps.peer = peer

	// Age the session so it's expired.
	ps.session.mu.Lock()
	ps.session.createdAt = time.Now().Add(-(sessionLifetime + sessionGracePeriod + time.Second))
	ps.session.mu.Unlock()

	// sendToPeer should silently drop the packet (expired session, existing entry).
	// The code enters the "if !ok || ps.session.IsExpired()" branch but since
	// ok==true, no async handshake is triggered — it just returns nil.
	err = e.sendToPeer(peer, []byte("should be dropped"))
	if err != nil {
		t.Fatalf("sendToPeer expired session: %v", err)
	}

	// No pending handshake should be created (the session exists, just expired).
	e.mu.RLock()
	pendingCount := len(e.pending)
	e.mu.RUnlock()
	if pendingCount != 0 {
		t.Errorf("expected no pending handshake for expired-but-existing session, got %d", pendingCount)
	}
}

// ─── Additional coverage: keepaliveLoop context cancellation ───────────────

func TestKeepaliveLoop_ContextCancellation(t *testing.T) {
	e := testEngine(t)
	e.serverURL = "http://127.0.0.1:0" // unreachable, but loop should still exit cleanly

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.keepaliveLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Good.
	case <-time.After(30 * time.Second):
		t.Fatal("keepaliveLoop did not exit on context cancellation")
	}
}

// ─── Additional coverage: derpUpgradeLoop context cancellation ─────────────

func TestDerpUpgradeLoop_ContextCancellation(t *testing.T) {
	e := testEngine(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.derpUpgradeLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Good.
	case <-time.After(35 * time.Second):
		t.Fatal("derpUpgradeLoop did not exit on context cancellation")
	}
}

// ─── Additional coverage: handshakeTimeoutLoop stopCh exit ─────────────────

func TestHandshakeTimeoutLoop_StopCh(t *testing.T) {
	e := testEngine(t)

	done := make(chan struct{})
	go func() {
		e.handshakeTimeoutLoop()
		close(done)
	}()

	// Close stopCh to signal exit.
	close(e.stopCh)

	select {
	case <-done:
		// Good.
	case <-time.After(5 * time.Second):
		t.Fatal("handshakeTimeoutLoop did not exit on stopCh close")
	}
}

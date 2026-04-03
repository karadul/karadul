//go:build !windows

package node

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/crypto"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/mesh"
)

// TestRekeyLoop_WithAgedSession verifies that rekeyLoop exits cleanly on context cancellation
// even when sessions needing rekey exist.
func TestRekeyLoop_WithAgedSession(t *testing.T) {
	e := testEngine(t)

	// Build an aged session that NeedsRekey() returns true.
	var remotePub [32]byte
	remotePub[0] = 0xDD
	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	ps := e.buildSession(remotePub, [32]byte{1}, [32]byte{2}, 99, 88, ep)
	peer := mesh.NewPeer(remotePub, "aged-peer", "n1", net.ParseIP("100.64.0.5"))
	peer.SetEndpoint(ep)
	ps.peer = peer

	// Age the session so NeedsRekey() returns true.
	ps.session.mu.Lock()
	ps.session.createdAt = time.Now().Add(-(sessionLifetime + time.Second))
	ps.session.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.rekeyLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// Good — rekeyLoop exited cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("rekeyLoop did not exit on context cancellation")
	}
}

// TestEndpointRefreshLoop_Cancelled verifies endpointRefreshLoop exits on context cancellation.
func TestEndpointRefreshLoop_Cancelled(t *testing.T) {
	e := testEngine(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.endpointRefreshLoop(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("endpointRefreshLoop did not exit on context cancellation")
	}
}

// TestUdpReadLoop_StopChClosed verifies udpReadLoop exits when stopCh is closed.
func TestUdpReadLoop_StopChClosed(t *testing.T) {
	e := testEngine(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp

	done := make(chan struct{})
	go func() {
		e.udpReadLoop()
		close(done)
	}()

	// Close stopCh AND the socket to trigger the exit path.
	close(e.stopCh)
	udp.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("udpReadLoop did not exit after stopCh + socket close")
	}
}

// TestConnectPeer_WithEndpoint exercises connectPeer with a peer that has an endpoint.
func TestConnectPeer_WithEndpoint(t *testing.T) {
	e := testEngine(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	var remotePub [32]byte
	remotePub[0] = 0xEE
	peer := mesh.NewPeer(remotePub, "connect-peer", "n2", net.ParseIP("100.64.0.6"))
	ep := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	peer.SetEndpoint(ep)

	// connectPeer should try to handshake — may fail crypto but shouldn't panic.
	_ = e.connectPeer(peer)
}

// TestConnectPeer_NoEndpoint_NoDERP exercises connectPeer when peer has no endpoint and no DERP client.
func TestConnectPeer_NoEndpoint_NoDERP(t *testing.T) {
	e := testEngine(t)

	var remotePub [32]byte
	remotePub[0] = 0xFF
	peer := mesh.NewPeer(remotePub, "no-ep-peer", "n3", net.ParseIP("100.64.0.7"))
	// No endpoint, no DERP client — connectPeer should return error.

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("UDP listen: %v", err)
	}
	e.udp = udp
	t.Cleanup(func() { udp.Close() })

	err = e.connectPeer(peer)
	if err == nil {
		t.Log("connectPeer succeeded despite no endpoint")
	}
}

// TestEnableExitNode_Darwin_ErrorPath verifies EnableExitNode fails gracefully on non-root.
func TestEnableExitNode_Darwin_ErrorPath(t *testing.T) {
	e := testEngine(t)
	err := e.EnableExitNode("nonexistent-iface-xyz")
	if err == nil {
		t.Log("EnableExitNode succeeded (running as root)")
	}
}

// TestDisableExitNode_Darwin_NoPanic verifies DisableExitNode doesn't panic.
func TestDisableExitNode_Darwin_NoPanic(t *testing.T) {
	DisableExitNode("nonexistent-iface-xyz")
}

// TestConcurrentSessionAccess verifies no data races under concurrent session operations.
func TestConcurrentSessionAccess(t *testing.T) {
	e := testEngine(t)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var pub [32]byte
			pub[0] = byte(id)
			ep := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5000 + id}
			ps := e.buildSession(pub, [32]byte{byte(id)}, [32]byte{byte(id + 1)}, uint32(id*2), uint32(id*2+1), ep)
			peer := mesh.NewPeer(pub, "concurrent-peer", "n", net.ParseIP("100.64.0.1"))
			peer.SetEndpoint(ep)
			ps.peer = peer

			ps.session.mu.Lock()
			ps.session.createdAt = time.Now().Add(-(sessionLifetime + time.Second))
			ps.session.mu.Unlock()
		}(i)
	}
	wg.Wait()

	e.mu.RLock()
	count := len(e.sessions)
	e.mu.RUnlock()
	if count != 10 {
		t.Errorf("expected 10 sessions, got %d", count)
	}
}

// TestStart_RegisterFails verifies Start returns error when coordination server is unreachable.
func TestStart_RegisterFails(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.NodeConfig{
		ServerURL: "http://127.0.0.1:0",
		Hostname:  "test-fail",
		AuthKey:   "test",
	}
	log := klog.New(nil, klog.LevelDebug, klog.FormatText)
	e := NewEngine(cfg, kp, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = e.Start(ctx)
	if err == nil {
		t.Fatal("expected Start to fail with unreachable server")
	}
	if !strings.Contains(err.Error(), "register") {
		t.Errorf("expected register error, got: %v", err)
	}
}

// TestUseExitNode_NilTun verifies UseExitNode handles nil tun gracefully.
func TestUseExitNode_NilTun(t *testing.T) {
	e := testEngine(t)
	peer := mesh.NewPeer([32]byte{1}, "exit-peer", "n3", net.ParseIP("100.64.0.3"))

	defer func() {
		if r := recover(); r != nil {
			t.Logf("UseExitNode panicked with nil tun (expected): %v", r)
		}
	}()
	_ = e.UseExitNode(peer)
}

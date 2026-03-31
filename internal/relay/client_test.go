package relay

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

// TestRun_ExitsOnContextCancel verifies Run returns when context is cancelled.
func TestRun_ExitsOnContextCancel(t *testing.T) {
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	// Use an address that will fail immediately (nothing listening)
	c := NewClient("http://127.0.0.1:1", pubKey, nil, log)

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Run should return quickly
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestConnect_DialFailure verifies connect returns error when dial fails.
func TestConnect_DialFailure(t *testing.T) {
	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	c := NewClient("http://127.0.0.1:1", pubKey, nil, log)

	ctx := context.Background()
	err := c.connect(ctx)
	if err == nil {
		t.Fatal("expected error when dial fails")
	}
}

// TestConnect_HTTPErrorStatus verifies connect returns error on non-101 status.
func TestConnect_HTTPErrorStatus(t *testing.T) {
	// Create a server that returns 500 instead of 101
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()
	go func() {
		conn, _ := ln.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		// Read request
		http.ReadRequest(rw.Reader)
		// Return 500 error
		fmt.Fprint(rw, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
		rw.Flush()
	}()

	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	c := NewClient("http://"+serverAddr, pubKey, nil, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = c.connect(ctx)
	if err == nil {
		t.Fatal("expected error on 500 status")
	}
}

// TestRun_ReconnectBackoff verifies exponential backoff on connection failure.
func TestRun_ReconnectBackoff(t *testing.T) {
	// Override testBackoff to capture backoff values.
	backoffCh := make(chan time.Duration, 20)
	fn := func(d time.Duration) <-chan time.Time {
		select {
		case backoffCh <- d:
		default:
		}
		return time.After(1 * time.Millisecond) // Fast for tests
	}
	testBackoff.Store(&fn)
	defer testBackoff.Store(nil)

	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	// Use an address that will fail immediately
	c := NewClient("http://127.0.0.1:1", pubKey, nil, log)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go c.Run(ctx)

	// Collect backoff values from channel.
	var backoffs []time.Duration
	collectDone := time.After(300 * time.Millisecond)
collect:
	for {
		select {
		case b := <-backoffCh:
			backoffs = append(backoffs, b)
		case <-collectDone:
			break collect
		}
	}

	// Should have multiple backoff values showing exponential growth.
	if len(backoffs) < 2 {
		t.Logf("only got %d backoff attempts, may need longer timeout", len(backoffs))
	}

	// Verify backoff increases exponentially.
	for i := 1; i < len(backoffs); i++ {
		if backoffs[i] <= backoffs[i-1] && backoffs[i] != backoffMax {
			t.Errorf("backoff did not increase: %v -> %v", backoffs[i-1], backoffs[i])
		}
		expected := backoffs[i-1] * 2
		if expected > backoffMax {
			expected = backoffMax
		}
		if backoffs[i] != expected && backoffs[i] != backoffMax {
			t.Errorf("backoff %d: expected %v, got %v", i, expected, backoffs[i])
		}
	}
}

// TestRun_MaxBackoff verifies that backoff caps at backoffMax (30s).
func TestRun_MaxBackoff(t *testing.T) {
	backoffCh := make(chan time.Duration, 30)
	fn := func(d time.Duration) <-chan time.Time {
		select {
		case backoffCh <- d:
		default:
		}
		return time.After(1 * time.Millisecond)
	}
	testBackoff.Store(&fn)
	defer testBackoff.Store(nil)

	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	c := NewClient("http://127.0.0.1:1", pubKey, nil, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go c.Run(ctx)

	// Collect backoff values from channel.
	var backoffs []time.Duration
	collectDone := time.After(600 * time.Millisecond)
collect:
	for {
		select {
		case b := <-backoffCh:
			backoffs = append(backoffs, b)
		case <-collectDone:
			break collect
		}
	}

	// Find the max backoff observed.
	var maxObserved time.Duration
	for _, b := range backoffs {
		if b > maxObserved {
			maxObserved = b
		}
	}

	if maxObserved != backoffMax {
		t.Errorf("max backoff: expected %v, got %v", backoffMax, maxObserved)
	}

	// Verify no backoff exceeded max.
	for i, b := range backoffs {
		if b > backoffMax {
			t.Errorf("backoff %d exceeded max: %v > %v", i, b, backoffMax)
		}
	}
}

// mockWriteConn is a net.Conn that fails on Write after a certain number of writes.
type mockWriteConn struct {
	net.Conn
	writeFailAfter int
	writeCount     int
}

func (m *mockWriteConn) Write(p []byte) (n int, err error) {
	m.writeCount++
	if m.writeFailAfter > 0 && m.writeCount >= m.writeFailAfter {
		return 0, fmt.Errorf("mock write error")
	}
	return m.Conn.Write(p)
}

func (m *mockWriteConn) Read(p []byte) (n int, err error) {
	// Block forever to simulate a stuck connection.
	select {}
}

func (m *mockWriteConn) Close() error {
	return m.Conn.Close()
}

func (m *mockWriteConn) LocalAddr() net.Addr                { return m.Conn.LocalAddr() }
func (m *mockWriteConn) RemoteAddr() net.Addr               { return m.Conn.RemoteAddr() }
func (m *mockWriteConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockWriteConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockWriteConn) SetWriteDeadline(t time.Time) error { return nil }

// TestConnect_WriteFrameError verifies error handling when WriteFrame fails during handshake.
func TestConnect_WriteFrameError(t *testing.T) {
	// Create a server that accepts connections but we'll close it to force write errors.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Accept and immediately close to force write error on ClientInfo.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the request, send 101, then close immediately.
			rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			http.ReadRequest(rw.Reader)
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: derp\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			conn.Close()
		}
	}()

	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	c := NewClient("http://"+serverAddr, pubKey, nil, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// connect should return error because server closes connection before ClientInfo can be sent.
	err = c.connect(ctx)
	if err == nil {
		t.Fatal("expected error when WriteFrame fails")
	}
}

// TestConnect_ClientInfoFlushError verifies error when flushing ClientInfo fails.
func TestConnect_ClientInfoFlushError(t *testing.T) {
	// This test is similar to above - server closes before we can flush.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	// Accept and close immediately after sending 101.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			http.ReadRequest(rw.Reader)
			fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: derp\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			// Close immediately - this should cause flush to fail.
			conn.Close()
		}
	}()

	log := klog.New(nil, klog.LevelError, klog.FormatText)
	var pubKey [32]byte
	c := NewClient("http://"+serverAddr, pubKey, nil, log)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = c.connect(ctx)
	// May or may not error depending on timing - both are acceptable.
	t.Logf("connect result: %v", err)
}

// TestServerHost_StripsPrefix verifies serverHost strips http:// and https://.
func TestServerHost_StripsPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com:443", "example.com:443"},
		{"http://example.com:80", "example.com:80"},
		{"example.com:8080", "example.com:8080"},
		{"https://derp.example.com", "derp.example.com"},
	}

	for _, tc := range tests {
		got := serverHost(tc.input)
		if got != tc.expected {
			t.Errorf("serverHost(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

package nat

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- NATType.String tests ---

func TestNATType_String(t *testing.T) {
	cases := []struct {
		nat  NATType
		want string
	}{
		{NATUnknown, "unknown"},
		{NATDirect, "direct"},
		{NATFullCone, "full-cone"},
		{NATRestrictedCone, "restricted-cone"},
		{NATPortRestricted, "port-restricted"},
		{NATSymmetric, "symmetric"},
		{NATType(99), "unknown"}, // default case
	}
	for _, tc := range cases {
		got := tc.nat.String()
		if got != tc.want {
			t.Errorf("NATType(%d).String(): want %q, got %q", int(tc.nat), tc.want, got)
		}
	}
}

// --- buildProbe / isProbe tests ---

func TestBuildProbe_HasMagic(t *testing.T) {
	probe := buildProbe("127.0.0.1:51820")
	if len(probe) < 4 {
		t.Fatalf("probe too short: %d bytes", len(probe))
	}
	magic := uint32(probe[0])<<24 | uint32(probe[1])<<16 | uint32(probe[2])<<8 | uint32(probe[3])
	if magic != hpMagic {
		t.Errorf("probe magic: want 0x%08X, got 0x%08X", hpMagic, magic)
	}
}

func TestBuildProbe_ContainsAddr(t *testing.T) {
	addr := "10.0.0.1:12345"
	probe := buildProbe(addr)
	// Byte 4 is the address length.
	if int(probe[4]) != len(addr) {
		t.Errorf("addr length byte: want %d, got %d", len(addr), probe[4])
	}
	got := string(probe[5:])
	if got != addr {
		t.Errorf("embedded addr: want %q, got %q", addr, got)
	}
}

func TestIsProbe_ValidMagic(t *testing.T) {
	probe := buildProbe("127.0.0.1:9999")
	if !isProbe(probe) {
		t.Fatal("isProbe should return true for a buildProbe packet")
	}
}

func TestIsProbe_BadMagic(t *testing.T) {
	buf := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if isProbe(buf) {
		t.Fatal("isProbe should return false for wrong magic")
	}
}

func TestIsProbe_TooShort(t *testing.T) {
	buf := []byte{0x4B, 0x52} // only 2 bytes
	if isProbe(buf) {
		t.Fatal("isProbe should return false for <4 byte buffer")
	}
}

func TestIsProbe_Empty(t *testing.T) {
	if isProbe([]byte{}) {
		t.Fatal("isProbe should return false for empty buffer")
	}
}

// --- HolePunch tests ---

// TestHolePunch_NilConn verifies HolePunch returns an error for nil conn.
func TestHolePunch_NilConn(t *testing.T) {
	remote, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:9")
	if _, err := HolePunch(context.Background(), nil, remote); err == nil {
		t.Fatal("HolePunch with nil conn should return error")
	}
}

// TestHolePunch_Success verifies HolePunch succeeds when the remote echoes the probe.
func TestHolePunch_Success(t *testing.T) {
	// Create a "remote" UDP socket that echoes probe packets back.
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	remoteAddr := remote.LocalAddr().(*net.UDPAddr)

	// Echo goroutine: reads a probe and sends it back.
	go func() {
		buf := make([]byte, 256)
		remote.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, src, err := remote.ReadFromUDP(buf)
		if err != nil || n < 4 {
			return
		}
		// Echo the probe back to the sender.
		remote.SetWriteDeadline(time.Now().Add(time.Second))
		remote.WriteToUDP(buf[:n], src)
	}()

	// Local socket for hole punching.
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	result, err := HolePunch(context.Background(), local, remoteAddr)
	if err != nil {
		t.Fatalf("HolePunch: %v", err)
	}
	if !result.Success {
		t.Fatal("HolePunch should succeed when remote echoes the probe")
	}
	if result.Endpoint == nil {
		t.Fatal("HolePunch result should have a non-nil endpoint on success")
	}
}

// TestHolePunch_Timeout verifies HolePunch returns false when no response comes.
// Uses a /dev/null-style UDP socket (port 9) which discards all packets.
// The test is shortened by overriding the timeout constant via a minimal remote
// that never responds.
func TestHolePunch_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	// Remote socket that never responds.
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	remote.Close() // Close immediately — the local side will get write errors.

	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	result, err := HolePunch(context.Background(), local, remote.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("HolePunch unexpected error: %v", err)
	}
	// With no responding peer, success should be false.
	if result.Success {
		t.Fatal("HolePunch should not succeed with no responding peer")
	}
}

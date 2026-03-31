package nat

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

const (
	hpRetries  = 10
	hpInterval = 500 * time.Millisecond
	hpTimeout  = 5 * time.Second
	hpJitter   = 50 * time.Millisecond
)

// hpMagic identifies hole punch probe packets: "KRDP".
var hpMagic uint32 = 0x4B524450

// HolePunchResult holds the outcome of a hole punch attempt.
type HolePunchResult struct {
	Success  bool
	Endpoint *net.UDPAddr
}

// PunchPacket is the probe packet sent during hole punching.
// Layout: magic(4) + local_endpoint_len(1) + local_endpoint(n)
type PunchPacket struct {
	Magic         uint32
	LocalEndpoint string
}

// HolePunch attempts UDP hole punching to remoteEndpoint.
// It sends probe packets and waits for an echo, indicating the path is open.
//
// Both peers must call HolePunch simultaneously — the coordination server
// should trigger them within ±50ms of each other.
func HolePunch(ctx context.Context, conn *net.UDPConn, remoteEndpoint *net.UDPAddr) (*HolePunchResult, error) {
	if conn == nil {
		return nil, fmt.Errorf("conn must not be nil")
	}

	probe := buildProbe(conn.LocalAddr().String())

	success := make(chan *net.UDPAddr, 1)
	done := make(chan struct{})

	// Receive goroutine: waits for a probe echo.
	go func() {
		buf := make([]byte, 256)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n >= 4 && isProbe(buf[:n]) {
				select {
				case success <- addr:
				default:
				}
				return
			}
		}
	}()

	// Send loop.
	ticker := time.NewTicker(hpInterval)
	defer ticker.Stop()
	timeout := time.NewTimer(hpTimeout)
	defer timeout.Stop()

	for i := 0; i < hpRetries; i++ {
		// Apply ±jitter (clamp negative to 0).
		jitter := time.Duration(rand.Int63n(int64(hpJitter*2))) - hpJitter
		if jitter < 0 {
			jitter = 0
		}
		time.Sleep(jitter)

		_ = conn.SetWriteDeadline(time.Now().Add(hpInterval))
		if _, err := conn.WriteToUDP(probe, remoteEndpoint); err != nil {
			continue
		}

		select {
		case addr := <-success:
			close(done)
			return &HolePunchResult{Success: true, Endpoint: addr}, nil
		case <-ticker.C:
		case <-timeout.C:
			close(done)
			return &HolePunchResult{Success: false}, nil
		case <-ctx.Done():
			close(done)
			return nil, ctx.Err()
		}
	}

	close(done)
	return &HolePunchResult{Success: false}, nil
}

// buildProbe builds a hole punch probe packet.
func buildProbe(localAddr string) []byte {
	addrBytes := []byte(localAddr)
	buf := make([]byte, 5+len(addrBytes))
	magic := hpMagic
	buf[0] = byte(magic >> 24)
	buf[1] = byte(magic >> 16)
	buf[2] = byte(magic >> 8)
	buf[3] = byte(magic)
	buf[4] = byte(len(addrBytes))
	copy(buf[5:], addrBytes)
	return buf
}

// isProbe returns true if buf looks like a hole punch probe.
func isProbe(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	magic := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	return magic == hpMagic
}

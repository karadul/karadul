package relay

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

const (
	// backoffBase is the initial reconnect wait.
	backoffBase = time.Second
	// backoffMax is the maximum reconnect wait.
	backoffMax = 30 * time.Second
)

// testBackoff is used by tests to override backoff behavior. If non-nil, it's called instead of time.After.
// Access is synchronized via atomic.Pointer to avoid races with test cleanup.
var testBackoff atomic.Pointer[func(time.Duration) <-chan time.Time]

// RecvFunc is called when a packet is received from the relay.
type RecvFunc func(src [32]byte, payload []byte)

// Client is a DERP relay client.
type Client struct {
	serverURL string
	pubKey    [32]byte
	log       *klog.Logger

	mu     sync.Mutex
	conn   net.Conn
	rw     *bufio.ReadWriter
	send   chan sendItem
	closed bool

	onRecv RecvFunc
}

type sendItem struct {
	dst     [32]byte
	payload []byte
}

// NewClient creates a DERP client that connects to serverURL.
// pubKey is the local node's public key, used to identify itself.
func NewClient(serverURL string, pubKey [32]byte, onRecv RecvFunc, log *klog.Logger) *Client {
	return &Client{
		serverURL: serverURL,
		pubKey:    pubKey,
		onRecv:    onRecv,
		send:      make(chan sendItem, 256),
		log:       log,
	}
}

// Run connects to the DERP server and maintains the connection until ctx is done.
// Reconnects with exponential backoff on failure.
func (c *Client) Run(ctx context.Context) {
	backoff := backoffBase
	for {
		if err := c.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.log.Warn("derp: connection failed, reconnecting",
				"err", err, "backoff", backoff.String())
			select {
			case <-func() <-chan time.Time {
				if fn := testBackoff.Load(); fn != nil {
					return (*fn)(backoff)
				}
				return time.After(backoff)
			}():
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > backoffMax {
				backoff = backoffMax
			}
			continue
		}
		backoff = backoffBase // reset on successful connection
		if ctx.Err() != nil {
			return
		}
	}
}

// connect dials the DERP server and serves frames until the connection drops.
func (c *Client) connect(ctx context.Context) error {
	// Reset send channel and closed flag for fresh reconnect.
	c.mu.Lock()
	c.send = make(chan sendItem, 256)
	c.closed = false
	c.mu.Unlock()

	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", serverHost(c.serverURL))
	if err != nil {
		return fmt.Errorf("dial derp: %w", err)
	}

	// HTTP upgrade.
	rw := bufio.NewReadWriter(bufio.NewReader(tcpConn), bufio.NewWriter(tcpConn))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: derp\r\nConnection: Upgrade\r\n\r\n",
		derpPath, serverHost(c.serverURL))
	if _, err := fmt.Fprint(rw, req); err != nil {
		tcpConn.Close()
		return err
	}
	if err := rw.Flush(); err != nil {
		tcpConn.Close()
		return err
	}

	// Read 101.
	_ = tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(rw.Reader, nil)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		tcpConn.Close()
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	_ = tcpConn.SetReadDeadline(time.Time{})

	c.mu.Lock()
	c.conn = tcpConn
	c.rw = rw
	c.mu.Unlock()

	// Close the TCP connection when ctx is cancelled so blocked reads return immediately.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-ctx.Done():
			tcpConn.Close()
		case <-connDone:
		}
	}()

	// Send ClientInfo.
	info := BuildClientInfo(c.pubKey)
	if err := WriteFrame(rw, FrameClientInfo, info); err != nil {
		tcpConn.Close()
		return err
	}
	if err := rw.Flush(); err != nil {
		tcpConn.Close()
		return err
	}

	c.log.Info("derp: connected", "server", c.serverURL)

	// Write goroutine.
	errCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-c.send:
				if !ok {
					return
				}
				payload := BuildSendPacket(item.dst, item.payload)
				_ = tcpConn.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
				if err := WriteFrame(rw, FrameSendPacket, payload); err != nil {
					errCh <- err
					return
				}
				if err := rw.Flush(); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Read loop.
	for {
		_ = tcpConn.SetReadDeadline(time.Now().Add(pingInterval * 2))
		frame, err := ReadFrame(rw)
		if err != nil {
			c.mu.Lock()
			if !c.closed {
				close(c.send)
				c.closed = true
			}
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				tcpConn.Close()
				return nil
			default:
				tcpConn.Close()
				return err
			}
		}
		switch frame.Type {
		case FrameRecvPacket:
			src, pkt, err := ParseRecvPacket(frame.Payload)
			if err == nil && c.onRecv != nil {
				c.onRecv(src, pkt)
			}
		case FramePing:
			_ = WriteFrame(rw, FramePong, nil)
			_ = rw.Flush()
		}
	}
}

// SendPacket queues a packet to be sent to dst via the relay.
func (c *Client) SendPacket(dst [32]byte, payload []byte) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	pkt := make([]byte, len(payload))
	copy(pkt, payload)
	select {
	case c.send <- sendItem{dst: dst, payload: pkt}:
	default:
		// Drop if channel full.
	}
}

// serverHost extracts "host:port" from a server URL or address.
func serverHost(url string) string {
	// Simple: strip http:// or https://
	for _, prefix := range []string{"https://", "http://"} {
		if len(url) > len(prefix) && url[:len(prefix)] == prefix {
			return url[len(prefix):]
		}
	}
	return url
}

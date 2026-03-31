package relay

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

const (
	derpPath           = "/derp"
	pingInterval       = 30 * time.Second
	clientWriteTimeout = 5 * time.Second
	maxClients         = 1024
)

// Server is a DERP relay server.
// Clients connect over HTTP (Upgrade: derp), identify themselves with their
// public key, and then exchange opaque encrypted frames.
type Server struct {
	mu      sync.RWMutex
	clients map[[32]byte]*serverClient
	log     *klog.Logger
}

type serverMsg struct {
	ft      FrameType
	payload []byte
}

type serverClient struct {
	pubKey [32]byte
	conn   net.Conn
	rw     *bufio.ReadWriter
	send   chan serverMsg
	done   chan struct{}
}

// NewServer creates a new DERP relay server.
func NewServer(log *klog.Logger) *Server {
	return &Server{
		clients: make(map[[32]byte]*serverClient),
		log:     log,
	}
}

// ServeHTTP implements http.Handler. It handles the HTTP upgrade to DERP.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != derpPath {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Upgrade") != "derp" {
		http.Error(w, "expected Upgrade: derp", http.StatusUpgradeRequired)
		return
	}

	hijack, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijack.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send HTTP 101 Switching Protocols.
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: derp\r\nConnection: Upgrade\r\n\r\n")
	if err := rw.Flush(); err != nil {
		conn.Close()
		return
	}

	s.handleClient(conn, rw)
}

// handleClient manages a single client connection from first frame to close.
func (s *Server) handleClient(conn net.Conn, rw *bufio.ReadWriter) {
	defer conn.Close()

	// First frame must be ClientInfo.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	frame, err := ReadFrame(rw)
	if err != nil {
		s.log.Debug("derp: read client info", "err", err)
		return
	}
	if frame.Type != FrameClientInfo || len(frame.Payload) < 32 {
		s.log.Debug("derp: bad client info frame")
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	var pubKey [32]byte
	copy(pubKey[:], frame.Payload[:32])

	// Enforce max client limit.
	s.mu.RLock()
	n := len(s.clients)
	s.mu.RUnlock()
	if n >= maxClients {
		s.log.Warn("derp: max clients reached, rejecting", "key", fmt.Sprintf("%x", pubKey[:4]))
		return
	}

	sc := &serverClient{
		pubKey: pubKey,
		conn:   conn,
		rw:     rw,
		send:   make(chan serverMsg, 64),
		done:   make(chan struct{}),
	}

	s.addClient(sc)
	defer s.removeClient(pubKey)

	// Notify others.
	s.broadcastPresence(pubKey, true)
	defer s.broadcastPresence(pubKey, false)

	s.log.Info("derp: client connected", "key", fmt.Sprintf("%x", pubKey[:4]))

	// Send goroutine.
	go func() {
		defer close(sc.done)
		for msg := range sc.send {
			_ = conn.SetWriteDeadline(time.Now().Add(clientWriteTimeout))
			if err := WriteFrame(rw, msg.ft, msg.payload); err != nil {
				return
			}
			if err := rw.Flush(); err != nil {
				return
			}
		}
	}()

	// Ping keepalive.
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()

	// Read loop.
	for {
		_ = conn.SetReadDeadline(time.Now().Add(pingInterval * 2))
		frame, err := ReadFrame(rw)
		if err != nil {
			return
		}
		switch frame.Type {
		case FrameSendPacket:
			dst, pkt, err := ParseSendPacket(frame.Payload)
			if err != nil {
				continue
			}
			s.route(pubKey, dst, pkt)
		case FramePing:
			sc.enqueue(serverMsg{ft: FramePong, payload: nil})
		}
	}
}

func (s *Server) route(src, dst [32]byte, pkt []byte) {
	s.mu.RLock()
	target, ok := s.clients[dst]
	s.mu.RUnlock()
	if !ok {
		return
	}
	payload := BuildRecvPacket(src, pkt)
	select {
	case target.send <- serverMsg{ft: FrameRecvPacket, payload: payload}:
	default:
		// Drop if channel full.
	}
}

func (s *Server) addClient(sc *serverClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.clients[sc.pubKey]; ok {
		close(old.send)
	}
	s.clients[sc.pubKey] = sc
}

func (s *Server) removeClient(pubKey [32]byte) {
	s.mu.Lock()
	sc, ok := s.clients[pubKey]
	if ok && sc.pubKey == pubKey {
		delete(s.clients, pubKey)
		close(sc.send)
	}
	s.mu.Unlock()
}

// enqueue safely sends a serverMsg without blocking (drops if full).
func (s *serverClient) enqueue(msg serverMsg) {
	select {
	case s.send <- msg:
	default:
	}
}

func (s *Server) broadcastPresence(pubKey [32]byte, present bool) {
	ft := FramePeerPresent
	if !present {
		ft = FramePeerGone
	}
	payload := make([]byte, 32)
	copy(payload, pubKey[:])

	// Hold RLock for the entire broadcast so that removeClient (which takes
	// the write lock before closing send channels) cannot run concurrently.
	// This prevents a send-on-closed-channel race.
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sc := range s.clients {
		if sc.pubKey == pubKey {
			continue
		}
		sc.enqueue(serverMsg{ft: ft, payload: payload})
	}
}

// Start binds the server and begins serving. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle(derpPath, s)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log.Info("derp relay server started", "addr", addr)

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

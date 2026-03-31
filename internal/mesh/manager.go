package mesh

import (
	"fmt"
	"net"
	"sync"
	"time"

	klog "github.com/karadul/karadul/internal/log"
)

// ConnectFunc is called when a new peer should have a tunnel established.
type ConnectFunc func(peer *Peer) error

// gcInterval is the interval for the gcLoop ticker. Overrideable for tests.
var gcInterval = time.Minute

// Manager manages the lifecycle of all mesh peers.
type Manager struct {
	mu      sync.RWMutex
	peers   map[[32]byte]*Peer // pubKey → peer
	byVIP   map[string]*Peer   // virtualIP string → peer
	log     *klog.Logger
	connect ConnectFunc

	done    chan struct{}
	stopped chan struct{}
}

// NewManager creates a Manager.
func NewManager(log *klog.Logger, connect ConnectFunc) *Manager {
	m := &Manager{
		peers:   make(map[[32]byte]*Peer),
		byVIP:   make(map[string]*Peer),
		log:     log,
		connect: connect,
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go m.gcLoop()
	return m
}

// Stop shuts down background goroutines and waits for them to finish.
func (m *Manager) Stop() {
	close(m.done)
	<-m.stopped
}

// AddOrUpdate adds a peer from the topology update, or updates an existing one.
func (m *Manager) AddOrUpdate(pubKey [32]byte, hostname, nodeID string, vip net.IP, endpoint string, routes []string) {
	m.mu.Lock()
	existing, ok := m.peers[pubKey]
	if !ok {
		peer := NewPeer(pubKey, hostname, nodeID, vip)
		peer.SetOnStateChange(m.onStateChange)
		if endpoint != "" {
			if addr, err := net.ResolveUDPAddr("udp4", endpoint); err == nil {
				peer.SetEndpoint(addr)
			}
		}
		for _, r := range routes {
			if _, cidr, err := net.ParseCIDR(r); err == nil {
				peer.Routes = append(peer.Routes, cidr)
			}
		}
		m.peers[pubKey] = peer
		m.byVIP[vip.String()] = peer
		m.mu.Unlock()

		m.log.Info("mesh: new peer discovered", "hostname", hostname, "vip", vip)
		if m.connect != nil {
			go func() {
				if err := m.connect(peer); err != nil {
					m.log.Warn("mesh: connect peer failed", "hostname", hostname, "err", err)
				}
			}()
		}
		return
	}

	// Update existing peer.
	existing.mu.Lock()
	existing.Hostname = hostname
	if endpoint != "" {
		if addr, err := net.ResolveUDPAddr("udp4", endpoint); err == nil {
			existing.Endpoint = addr
		}
	}
	existing.Routes = existing.Routes[:0]
	for _, r := range routes {
		if _, cidr, err := net.ParseCIDR(r); err == nil {
			existing.Routes = append(existing.Routes, cidr)
		}
	}
	if existing.State == PeerExpired {
		existing.State = PeerDiscovered
	}
	existing.mu.Unlock()
	m.mu.Unlock()
}

// Remove marks a peer as expired.
func (m *Manager) Remove(pubKey [32]byte) {
	m.mu.RLock()
	p, ok := m.peers[pubKey]
	m.mu.RUnlock()
	if ok {
		p.Transition(PeerExpired)
		m.log.Info("mesh: peer expired", "hostname", p.Hostname)
	}
}

// GetPeer returns the peer for pubKey.
func (m *Manager) GetPeer(pubKey [32]byte) (*Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.peers[pubKey]
	return p, ok
}

// GetPeerByVIP returns the peer whose virtual IP matches.
func (m *Manager) GetPeerByVIP(ip net.IP) (*Peer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.byVIP[ip.String()]
	return p, ok
}

// ListPeers returns all peers.
func (m *Manager) ListPeers() []*Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peers := make([]*Peer, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	return peers
}

// onStateChange logs peer state transitions.
func (m *Manager) onStateChange(p *Peer, from, to PeerState) {
	m.log.Info("mesh: peer state change",
		"hostname", p.Hostname,
		"from", from.String(),
		"to", to.String(),
	)
}

// gcLoop periodically checks for idle/expired peers.
func (m *Manager) gcLoop() {
	defer close(m.stopped)
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.mu.Lock()
			for _, p := range m.peers {
				p.IdleCheck()
			}
			for k, p := range m.peers {
				if p.IsExpired() {
					delete(m.peers, k)
					delete(m.byVIP, p.VirtualIP.String())
				}
			}
			m.mu.Unlock()
		}
	}
}

// PeerSummary returns a human-readable summary of a peer.
func PeerSummary(p *Peer) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ep := "(none)"
	if p.Endpoint != nil {
		ep = p.Endpoint.String()
	}
	shortID := p.NodeID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return fmt.Sprintf("%s (%s) state=%s vip=%s endpoint=%s",
		p.Hostname, shortID, p.State.String(), p.VirtualIP, ep)
}

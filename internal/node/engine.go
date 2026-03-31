// Package node implements the Karadul mesh node engine.
// It ties together the TUN device, crypto sessions, mesh peer management,
// coordination client, NAT traversal, and DERP relay into a single coherent
// packet-forwarding loop.
package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/karadul/karadul/internal/auth"
	"github.com/karadul/karadul/internal/config"
	"github.com/karadul/karadul/internal/coordinator"
	"github.com/karadul/karadul/internal/crypto"
	"github.com/karadul/karadul/internal/dns"
	klog "github.com/karadul/karadul/internal/log"
	"github.com/karadul/karadul/internal/mesh"
	"github.com/karadul/karadul/internal/nat"
	"github.com/karadul/karadul/internal/protocol"
	"github.com/karadul/karadul/internal/relay"
	"github.com/karadul/karadul/internal/tunnel"
)

const (
	keepaliveInterval    = 25 * time.Second
	endpointRefreshEvery = 30 * time.Second // how often to re-STUN and report endpoint
	derpUpgradeEvery     = 30 * time.Second // how often to try direct when currently relayed
	handshakeTimeout     = 5 * time.Second  // how long to wait for handshake resp
	rekeyCheckInterval   = 30 * time.Second // how often to scan for sessions needing rekey
)

// peerSession holds the transport state for one established peer channel.
type peerSession struct {
	peer       *mesh.Peer
	session    *Session
	endpoint   atomic.Pointer[net.UDPAddr] // nil = use DERP
	receiverID uint32                      // peer's local session ID (our message target)
	localID    uint32                      // our local session ID (peer sends this in data msgs)
}

// pendingHandshake tracks an in-progress initiator handshake.
type pendingHandshake struct {
	peer    *mesh.Peer
	hs      *crypto.HandshakeState
	localID uint32
	sentAt  time.Time
}

// Engine is the Karadul node engine.
type Engine struct {
	cfg *config.NodeConfig
	log *klog.Logger
	kp  crypto.KeyPair

	// Network I/O
	tun tunnel.Device
	udp *net.UDPConn

	// Mesh management
	manager  *mesh.Manager
	router   *mesh.Router
	topology *mesh.TopologyManager

	// DERP relay client (nil until needed)
	derpClient *relay.Client
	derpMu     sync.Mutex

	// DNS
	magic    *dns.MagicDNS
	resolver *dns.Resolver

	// Session state
	mu       sync.RWMutex
	sessions map[[32]byte]*peerSession    // pubKey  → active session
	byID     map[uint32]*peerSession      // localID → active session (for inbound data)
	pending  map[uint32]*pendingHandshake // localID → in-progress initiator HS

	// Monotonic session ID counter (atomic to avoid holding mu during nextID)
	idCounter atomic.Uint32

	// Coordination
	serverURL string
	nodeID    string
	virtualIP net.IP
	publicEP  atomic.Pointer[net.UDPAddr] // our NAT-translated public endpoint

	// ACL
	acl *auth.Engine

	// DNS restore function (undoes system DNS override on shutdown)
	dnsRestore func() error

	// Metrics (atomic counters)
	metricPacketsTx atomic.Uint64
	metricPacketsRx atomic.Uint64
	metricBytesTx   atomic.Uint64
	metricBytesRx   atomic.Uint64

	// Lifecycle
	stopCh chan struct{}
	cancel context.CancelFunc // used by local API /shutdown
	ctx    context.Context    // set by Start

	// Buffer pool — reuse large slices for packet I/O
	bufPool sync.Pool

	// Semaphore to limit concurrent UDP packet handler goroutines.
	udpSem chan struct{}
}

// NewEngine creates a node Engine from cfg and the pre-loaded key pair.
func NewEngine(cfg *config.NodeConfig, kp crypto.KeyPair, log *klog.Logger) *Engine {
	e := &Engine{
		cfg:       cfg,
		log:       log,
		kp:        kp,
		sessions:  make(map[[32]byte]*peerSession),
		byID:      make(map[uint32]*peerSession),
		pending:   make(map[uint32]*pendingHandshake),
		serverURL: cfg.ServerURL,
		stopCh:    make(chan struct{}),
		magic:     dns.NewMagicDNS(),
		acl:       auth.NewEngine(auth.ACLPolicy{}), // default allow-all
		udpSem:    make(chan struct{}, 256),
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, protocol.MaxPacketSize)
				return &b
			},
		},
	}
	return e
}

// Start registers with the coordination server, brings up the TUN device,
// and begins the packet forwarding loop. Blocks until ctx is cancelled.
func (e *Engine) Start(ctx context.Context) error {
	// Wrap ctx so we can cancel from the local API /shutdown endpoint.
	ctx, e.cancel = context.WithCancel(ctx)
	e.ctx = ctx

	// Register with coordination server.
	if err := e.register(ctx); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	// Bind UDP socket first so we have a port for STUN.
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{Port: e.cfg.ListenPort})
	if err != nil {
		return fmt.Errorf("bind udp: %w", err)
	}
	e.udp = udp
	e.log.Info("udp socket bound", "addr", udp.LocalAddr())

	// STUN: discover public endpoint and report it to coordination server.
	if ep, err := e.discoverEndpoint(); err != nil {
		e.log.Warn("stun discovery failed, will retry later", "err", err)
	} else {
		e.publicEP.Store(ep)
		e.log.Info("stun: public endpoint", "addr", ep)
		_ = e.reportEndpoint(ctx, ep.String())
	}

	// Bring up TUN device.
	dev, err := tunnel.CreateTUN("")
	if err != nil {
		udp.Close()
		return fmt.Errorf("create tun: %w", err)
	}
	e.tun = dev
	e.log.Info("tun device created", "name", dev.Name())

	// Assign virtual IP (/10 mask for CGNAT).
	if err := dev.SetAddr(e.virtualIP, 10); err != nil {
		return fmt.Errorf("set tun addr: %w", err)
	}

	// Add mesh subnet route.
	_, meshNet, _ := net.ParseCIDR("100.64.0.0/10")
	if err := dev.AddRoute(meshNet); err != nil {
		e.log.Warn("add mesh route failed (may already exist)", "err", err)
	}

	// Initialise mesh subsystems.
	e.manager = mesh.NewManager(e.log, e.connectPeer)
	e.router = mesh.NewRouter(e.manager)
	e.topology = mesh.NewTopologyManager(e.manager, e.kp.Public, e.log)

	// DNS resolver.
	var dnsRestore func() error
	if e.cfg.DNS.Enabled {
		const dnsAddr = "100.64.0.53:53"
		upstream := e.cfg.DNS.Upstream
		if upstream == "" {
			upstream = "1.1.1.1:53"
		}
		e.resolver = dns.NewResolver(dnsAddr, upstream, e.magic, e.log)
		go func() {
			if err := e.resolver.Start(); err != nil && ctx.Err() == nil {
				e.log.Error("dns resolver stopped", "err", err)
			}
		}()
		// Override system DNS to point at our resolver.
		if restore, err := dns.Override(dnsAddr); err != nil {
			e.log.Warn("dns override failed", "err", err)
		} else {
			dnsRestore = restore
			e.log.Info("dns override applied", "addr", dnsAddr)
		}
	}
	e.dnsRestore = dnsRestore

	// Start local Unix socket API (for karadul status/peers).
	go e.serveLocalAPI(ctx)

	// Start main goroutines.
	go e.tunReadLoop()
	go e.udpReadLoop()
	go e.pollLoop(ctx)
	go e.keepaliveLoop(ctx)
	go e.endpointRefreshLoop(ctx)
	go e.handshakeTimeoutLoop()
	go e.derpUpgradeLoop(ctx)
	go e.rekeyLoop(ctx)

	<-ctx.Done()
	return e.shutdown()
}

// shutdown tears down all engine subsystems.
func (e *Engine) shutdown() error {
	close(e.stopCh)
	if e.tun != nil {
		_ = e.tun.Close()
	}
	if e.udp != nil {
		_ = e.udp.Close()
	}
	if e.resolver != nil {
		_ = e.resolver.Close()
	}
	// Restore system DNS if we overrode it.
	if e.dnsRestore != nil {
		if err := e.dnsRestore(); err != nil {
			e.log.Warn("dns restore failed", "err", err)
		} else {
			e.log.Info("dns restored")
		}
	}
	if e.manager != nil {
		e.manager.Stop()
	}
	return nil
}

// ─── Registration ─────────────────────────────────────────────────────────────

type registerReq struct {
	PublicKey  string   `json:"publicKey"`
	Hostname   string   `json:"hostname"`
	AuthKey    string   `json:"authKey"`
	Routes     []string `json:"routes,omitempty"`
	IsExitNode bool     `json:"isExitNode,omitempty"`
}

type registerResp struct {
	NodeID    string `json:"nodeId"`
	VirtualIP string `json:"virtualIp"`
	Hostname  string `json:"hostname"`
}

func (e *Engine) register(ctx context.Context) error {
	hostname := e.cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	req := registerReq{
		PublicKey:  e.kp.Public.String(),
		Hostname:   hostname,
		AuthKey:    e.cfg.AuthKey,
		Routes:     e.cfg.AdvertiseRoutes,
		IsExitNode: e.cfg.AdvertiseExitNode,
	}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.serverURL+"/api/v1/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}

	var rr registerResp
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	e.nodeID = rr.NodeID
	e.virtualIP = net.ParseIP(rr.VirtualIP)
	if e.virtualIP == nil {
		return fmt.Errorf("invalid virtual IP %q", rr.VirtualIP)
	}
	e.log.Info("registered",
		"nodeId", rr.NodeID,
		"virtualIp", rr.VirtualIP,
		"hostname", rr.Hostname)
	return nil
}

// ─── STUN / Endpoint discovery ───────────────────────────────────────────────

// discoverEndpoint uses STUN to learn our public UDP endpoint.
func (e *Engine) discoverEndpoint() (*net.UDPAddr, error) {
	for _, server := range nat.DefaultSTUNServers {
		result, err := nat.BindingRequest(e.udp, server)
		if err != nil {
			continue
		}
		return result.PublicAddr, nil
	}
	return nil, fmt.Errorf("all STUN servers unreachable")
}

// reportEndpoint tells the coordination server our current public endpoint.
func (e *Engine) reportEndpoint(ctx context.Context, endpoint string) error {
	type req struct {
		Endpoint string `json:"endpoint"`
		RxBytes  int64  `json:"rxBytes"`
		TxBytes  int64  `json:"txBytes"`
	}
	body, _ := json.Marshal(req{
		Endpoint: endpoint,
		RxBytes:  int64(e.metricBytesRx.Load()),
		TxBytes:  int64(e.metricBytesTx.Load()),
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.serverURL+"/api/v1/update-endpoint", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	e.signRequest(httpReq, body)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// endpointRefreshLoop re-discovers our public endpoint periodically.
func (e *Engine) endpointRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(endpointRefreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if ep, err := e.discoverEndpoint(); err == nil {
				prevEP := e.publicEP.Load()
				e.publicEP.Store(ep)
				if prevEP == nil || ep.String() != prevEP.String() {
					e.log.Info("endpoint changed", "addr", ep)
					_ = e.reportEndpoint(ctx, ep.String())
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ─── Poll loop ────────────────────────────────────────────────────────────────

func (e *Engine) pollLoop(ctx context.Context) {
	var sinceVersion int64
	backoff := time.Second
	for {
		state, err := e.poll(ctx, sinceVersion)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Warn("poll error", "err", err, "retry", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		sinceVersion = state.Version
		e.topology.Apply(*state)
		e.updateMagicDNS(state.Nodes)
		e.applyACL(state.ACL)
		// Apply DERP map if present.
		if state.DERPMap != nil && len(state.DERPMap.Regions) > 0 {
			e.ensureDERPClient(ctx, state.DERPMap)
		}
	}
}

func (e *Engine) poll(ctx context.Context, sinceVersion int64) (*coordinator.NetworkState, error) {
	body, _ := json.Marshal(map[string]int64{"sinceVersion": sinceVersion})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.serverURL+"/api/v1/poll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	e.signRequest(req, body)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var state coordinator.NetworkState
	return &state, json.NewDecoder(resp.Body).Decode(&state)
}

// signRequest attaches HMAC-BLAKE2s authentication headers.
// Both sides compute HMAC with the node's public key so the coordinator
// can verify using only the registered public key.
func (e *Engine) signRequest(req *http.Request, body []byte) {
	msg := append([]byte(req.Method+"\n"+req.URL.RequestURI()+"\n"), body...)
	mac := crypto.HMAC(e.kp.Public[:], msg)
	req.Header.Set("X-Karadul-Key", e.kp.Public.String())
	req.Header.Set("X-Karadul-Sig", base64.StdEncoding.EncodeToString(mac[:]))
}

// updateMagicDNS rebuilds the magic DNS hostname table.
func (e *Engine) updateMagicDNS(nodes []*coordinator.Node) {
	entries := make(map[string]net.IP, len(nodes))
	for _, n := range nodes {
		if n.Status == coordinator.NodeStatusActive {
			if ip := net.ParseIP(n.VirtualIP); ip != nil {
				entries[n.Hostname] = ip
			}
		}
	}
	e.magic.Update(entries)
}

// applyACL converts the coordinator's ACL policy and loads it into the engine's ACL engine.
func (e *Engine) applyACL(policy coordinator.ACLPolicy) {
	if len(policy.Rules) == 0 {
		return // keep existing policy
	}
	authRules := make([]auth.ACLRule, 0, len(policy.Rules))
	for _, r := range policy.Rules {
		authRules = append(authRules, auth.ACLRule{
			Action: r.Action,
			Src:    r.Src,
			Dst:    r.Dst,
			Ports:  r.Ports,
		})
	}
	e.acl.UpdatePolicy(auth.ACLPolicy{
		Version: policy.Version,
		Rules:   authRules,
	})
}

// ─── DERP client ──────────────────────────────────────────────────────────────

// ensureDERPClient starts a DERP client for the first usable server in the map.
func (e *Engine) ensureDERPClient(ctx context.Context, dm *coordinator.DERPMap) {
	e.derpMu.Lock()
	defer e.derpMu.Unlock()
	if e.derpClient != nil {
		return // already running
	}
	// Pick first node from the map.
	for _, region := range dm.Regions {
		for _, node := range region.Nodes {
			serverURL := fmt.Sprintf("http://%s:%d", node.HostName, node.DERPPort)
			c := relay.NewClient(serverURL, e.kp.Public, e.onDERPRecv, e.log)
			e.derpClient = c
			go c.Run(ctx)
			e.log.Info("derp client started", "server", serverURL)
			return
		}
	}
}

// onDERPRecv is called when a packet arrives via DERP relay.
func (e *Engine) onDERPRecv(src [32]byte, payload []byte) {
	// Treat DERP-delivered packets the same as UDP packets (no source addr).
	if len(payload) == 0 {
		return
	}
	ptype, err := protocol.ParseType(payload)
	if err != nil {
		return
	}
	switch ptype {
	case protocol.TypeHandshakeInit:
		e.handleHandshakeInit(nil, payload)
	case protocol.TypeHandshakeResp:
		e.handleHandshakeResp(nil, payload)
	case protocol.TypeData:
		e.handleData(nil, payload)
	}
}

// derpUpgradeLoop periodically tries to upgrade DERP sessions to direct.
func (e *Engine) derpUpgradeLoop(ctx context.Context) {
	ticker := time.NewTicker(derpUpgradeEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.tryUpgradeToDirect()
		case <-ctx.Done():
			return
		}
	}
}

// tryUpgradeToDirect attempts to re-establish direct paths for relayed peers.
func (e *Engine) tryUpgradeToDirect() {
	e.mu.RLock()
	var toUpgrade []*peerSession
	for _, ps := range e.sessions {
		if ps.endpoint.Load() == nil && ps.peer != nil {
			// Currently relayed; try direct if endpoint is known.
			if ps.peer.GetEndpoint() != nil {
				toUpgrade = append(toUpgrade, ps)
			}
		}
	}
	e.mu.RUnlock()

	for _, ps := range toUpgrade {
		e.log.Debug("trying to upgrade DERP → direct", "peer", ps.peer.Hostname)
		_ = e.initiateHandshake(ps.peer)
	}
}

// ─── Keepalive ────────────────────────────────────────────────────────────────

func (e *Engine) keepaliveLoop(ctx context.Context) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = e.sendPing(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (e *Engine) sendPing(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.serverURL+"/api/v1/ping", bytes.NewReader(nil))
	if err != nil {
		return err
	}
	e.signRequest(req, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ─── TUN read loop ───────────────────────────────────────────────────────────

func (e *Engine) tunReadLoop() {
	for {
		bufp := e.bufPool.Get().(*[]byte)
		buf := *bufp
		n, err := e.tun.Read(buf)
		if err != nil {
			e.bufPool.Put(bufp)
			select {
			case <-e.stopCh:
				return
			default:
				e.log.Debug("tun read", "err", err)
				continue
			}
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		e.bufPool.Put(bufp)

		src, dst, err := tunnel.PacketSrcDst(packet)
		if err != nil {
			continue
		}
		// ACL check on outbound packet.
		if src != nil && dst != nil && !e.acl.Allow(src, dst, packetDstPort(packet)) {
			e.log.Debug("acl drop outbound", "src", src, "dst", dst)
			continue
		}
		peer, err := e.router.RoutePacket(dst)
		if err != nil {
			e.log.Debug("no route", "dst", dst)
			continue
		}
		if err := e.sendToPeer(peer, packet); err != nil {
			e.log.Debug("send", "peer", peer.Hostname, "err", err)
		}
	}
}

// ─── UDP read loop ────────────────────────────────────────────────────────────

func (e *Engine) udpReadLoop() {
	for {
		bufp := e.bufPool.Get().(*[]byte)
		buf := *bufp
		n, addr, err := e.udp.ReadFromUDP(buf)
		if err != nil {
			e.bufPool.Put(bufp)
			select {
			case <-e.stopCh:
				return
			default:
				e.log.Debug("udp read", "err", err)
				continue
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		e.bufPool.Put(bufp)
		select {
		case e.udpSem <- struct{}{}:
			go func() {
				e.handleUDPPacket(addr, pkt)
				<-e.udpSem
			}()
		default:
			// Semaphore full — drop packet to avoid goroutine explosion
		}
	}
}

func (e *Engine) handleUDPPacket(addr *net.UDPAddr, pkt []byte) {
	ptype, err := protocol.ParseType(pkt)
	if err != nil {
		return
	}
	switch ptype {
	case protocol.TypeHandshakeInit:
		e.handleHandshakeInit(addr, pkt)
	case protocol.TypeHandshakeResp:
		e.handleHandshakeResp(addr, pkt)
	case protocol.TypeData:
		e.handleData(addr, pkt)
	case protocol.TypeKeepalive:
		// Do nothing; just proves path is alive.
	}
}

// ─── Packet sending ───────────────────────────────────────────────────────────

// sendToPeer encrypts packet and sends it to peer, falling back to DERP if needed.
func (e *Engine) sendToPeer(peer *mesh.Peer, packet []byte) error {
	e.mu.RLock()
	ps, ok := e.sessions[peer.PublicKey]
	e.mu.RUnlock()

	if !ok || ps.session.IsExpired() {
		if !ok {
			// First packet to this peer — initiate handshake asynchronously.
			go func() {
				if err := e.connectPeer(peer); err != nil {
					e.log.Warn("connect peer", "peer", peer.Hostname, "err", err)
				}
			}()
		}
		return nil // drop; retransmission is the application's responsibility
	}

	counter, ct, err := ps.session.Encrypt(packet)
	if err != nil {
		return err
	}

	wireMsg := (&protocol.MsgData{
		ReceiverIndex: ps.receiverID,
		Counter:       counter,
		Ciphertext:    ct,
	}).MarshalBinary()

	// Prefer direct UDP; fall back to DERP.
	ep := ps.endpoint.Load()
	if ep == nil {
		ep = peer.GetEndpoint()
	}
	if ep != nil {
		_, err = e.udp.WriteToUDP(wireMsg, ep)
		if err == nil {
			e.metricPacketsTx.Add(1)
			e.metricBytesTx.Add(uint64(len(packet)))
		}
		return err
	}

	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != nil {
		dc.SendPacket(peer.PublicKey, wireMsg)
		e.metricPacketsTx.Add(1)
		e.metricBytesTx.Add(uint64(len(packet)))
		return nil
	}
	return fmt.Errorf("no path to peer %s (no endpoint, no DERP)", peer.Hostname)
}

// ─── Handshake — initiator ────────────────────────────────────────────────────

// initiateHandshake starts a Noise IK handshake with peer.
// If we already have a pending handshake for this peer, it is a no-op.
func (e *Engine) initiateHandshake(peer *mesh.Peer) error {
	// Check for existing pending handshake.
	e.mu.RLock()
	for _, ph := range e.pending {
		if ph.peer.PublicKey == peer.PublicKey {
			e.mu.RUnlock()
			return nil // already in progress
		}
	}
	e.mu.RUnlock()

	hs, err := crypto.InitiatorHandshake(e.kp, peer.PublicKey)
	if err != nil {
		return err
	}
	msg1, err := hs.WriteMessage1()
	if err != nil {
		return err
	}

	localID := e.nextID()
	init := &protocol.MsgHandshakeInit{SenderIndex: localID}
	copy(init.Ephemeral[:], msg1[:32])
	copy(init.EncStatic[:], msg1[32:80])
	copy(init.EncPayload[:], msg1[80:96])

	e.mu.Lock()
	e.pending[localID] = &pendingHandshake{
		peer:    peer,
		hs:      hs,
		localID: localID,
		sentAt:  time.Now(),
	}
	e.mu.Unlock()

	peer.Transition(mesh.PeerConnecting)

	wire := init.MarshalBinary()
	ep := peer.GetEndpoint()
	if ep != nil {
		_, err = e.udp.WriteToUDP(wire, ep)
		return err
	}

	// Send via DERP if no direct endpoint.
	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != nil {
		dc.SendPacket(peer.PublicKey, wire)
		return nil
	}
	return fmt.Errorf("no path to peer %s for handshake", peer.Hostname)
}

// handleHandshakeInit processes an incoming initiator message (we are responder).
func (e *Engine) handleHandshakeInit(addr *net.UDPAddr, pkt []byte) {
	init, err := protocol.UnmarshalMsgHandshakeInit(pkt)
	if err != nil {
		return
	}

	hs, err := crypto.ResponderHandshake(e.kp)
	if err != nil {
		return
	}

	var msg1 [96]byte
	copy(msg1[:32], init.Ephemeral[:])
	copy(msg1[32:80], init.EncStatic[:])
	copy(msg1[80:96], init.EncPayload[:])

	if err := hs.ReadMessage1(msg1[:]); err != nil {
		e.log.Debug("noise msg1 failed", "err", err)
		return
	}

	msg2, err := hs.WriteMessage2()
	if err != nil {
		return
	}

	localID := e.nextID()
	resp := &protocol.MsgHandshakeResp{
		SenderIndex:   localID,
		ReceiverIndex: init.SenderIndex,
	}
	copy(resp.Ephemeral[:], msg2[:32])
	copy(resp.EncPayload[:], msg2[32:48])

	sendKey, recvKey, err := hs.TransportKeys()
	if err != nil {
		return
	}

	remoteKey := hs.RemoteStaticKey()
	ps := e.buildSession(remoteKey, sendKey, recvKey, localID, init.SenderIndex, addr)

	// Update peer state.
	if p, ok := e.manager.GetPeer(remoteKey); ok {
		if addr != nil {
			p.SetEndpoint(addr)
			ps.endpoint.Store(addr)
		}
		p.Transition(mesh.PeerDirect)
		ps.peer = p
	}

	// Send response.
	wire := resp.MarshalBinary()
	if addr != nil {
		_, _ = e.udp.WriteToUDP(wire, addr)
	} else {
		// Arrived via DERP — respond via DERP.
		e.derpMu.Lock()
		dc := e.derpClient
		e.derpMu.Unlock()
		if dc != nil {
			dc.SendPacket(remoteKey, wire)
		}
	}
}

// handleHandshakeResp completes an initiated handshake (we are initiator).
func (e *Engine) handleHandshakeResp(addr *net.UDPAddr, pkt []byte) {
	resp, err := protocol.UnmarshalMsgHandshakeResp(pkt)
	if err != nil {
		return
	}

	e.mu.Lock()
	ph, ok := e.pending[resp.ReceiverIndex]
	if ok {
		delete(e.pending, resp.ReceiverIndex)
	}
	e.mu.Unlock()

	if !ok {
		e.log.Debug("handshake resp for unknown id", "id", resp.ReceiverIndex)
		return
	}

	var msg2 [48]byte
	copy(msg2[:32], resp.Ephemeral[:])
	copy(msg2[32:48], resp.EncPayload[:])

	if err := ph.hs.ReadMessage2(msg2[:]); err != nil {
		e.log.Debug("noise msg2 failed", "err", err)
		return
	}

	sendKey, recvKey, err := ph.hs.TransportKeys()
	if err != nil {
		return
	}

	ps := e.buildSession(ph.peer.PublicKey, sendKey, recvKey, resp.ReceiverIndex, resp.SenderIndex, addr)

	if addr != nil {
		ph.peer.SetEndpoint(addr)
		ps.endpoint.Store(addr)
		ph.peer.Transition(mesh.PeerDirect)
	} else {
		ph.peer.Transition(mesh.PeerRelayed)
	}
	ps.peer = ph.peer

	e.log.Info("handshake complete",
		"peer", ph.peer.Hostname,
		"path", pathName(addr))
}

// buildSession stores a newly established session in both maps.
func (e *Engine) buildSession(remotePub crypto.Key, sendKey, recvKey [32]byte, localID, receiverID uint32, ep *net.UDPAddr) *peerSession {
	ps := &peerSession{
		session: NewSession(sendKey, recvKey, func() {
			// Trigger re-key when session expires.
		}),
		localID:    localID,
		receiverID: receiverID,
	}
	ps.endpoint.Store(ep)

	e.mu.Lock()
	e.sessions[remotePub] = ps
	e.byID[localID] = ps
	e.mu.Unlock()
	return ps
}

// handleData decrypts an incoming data packet and writes it to the TUN device.
func (e *Engine) handleData(addr *net.UDPAddr, pkt []byte) {
	msg, err := protocol.UnmarshalMsgData(pkt)
	if err != nil {
		return
	}

	e.mu.RLock()
	ps, ok := e.byID[msg.ReceiverIndex]
	e.mu.RUnlock()
	if !ok {
		return
	}

	plain, err := ps.session.Decrypt(msg.Counter, msg.Ciphertext)
	if err != nil {
		e.log.Debug("decrypt", "err", err)
		return
	}

	if ps.peer != nil {
		ps.peer.Touch()
		// If we received a direct packet, update endpoint and upgrade state.
		if addr != nil && ps.endpoint.Load() == nil {
			ps.peer.SetEndpoint(addr)
			ps.endpoint.Store(addr)
			ps.peer.Transition(mesh.PeerDirect)
		}
	}

	// ACL check: parse src/dst from decrypted IP packet.
	src, dst, _ := tunnel.PacketSrcDst(plain)
	if src != nil && dst != nil {
		if !e.acl.Allow(src, dst, packetDstPort(plain)) {
			e.log.Debug("acl drop inbound", "src", src, "dst", dst)
			return
		}
	}

	e.metricPacketsRx.Add(1)
	e.metricBytesRx.Add(uint64(len(plain)))

	if _, err := e.tun.Write(plain); err != nil {
		e.log.Debug("tun write", "err", err)
	}
}

// ─── Handshake timeout / cleanup ─────────────────────────────────────────────

// handshakeTimeoutLoop removes pending handshakes that never got a response.
func (e *Engine) handshakeTimeoutLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.mu.Lock()
			for id, ph := range e.pending {
				if time.Since(ph.sentAt) > handshakeTimeout {
					delete(e.pending, id)
					ph.peer.Transition(mesh.PeerDiscovered) // allow retry
					e.log.Debug("handshake timeout", "peer", ph.peer.Hostname)
				}
			}
			e.mu.Unlock()
		case <-e.stopCh:
			return
		}
	}
}

// ─── connectPeer: NAT traversal logic ────────────────────────────────────────

// connectPeer is called by the mesh manager when a new peer appears in the topology.
// It runs the full NAT traversal attempt: direct → hole punch → DERP.
func (e *Engine) connectPeer(peer *mesh.Peer) error {
	e.log.Info("connecting to peer",
		"hostname", peer.Hostname,
		"vip", peer.VirtualIP,
		"endpoint", peer.GetEndpoint())

	// If we have a known endpoint, try a direct handshake first.
	if ep := peer.GetEndpoint(); ep != nil {
		if err := e.initiateHandshake(peer); err == nil {
			return nil
		}
	}

	// Try UDP hole punching (requires coordination server endpoint exchange).
	if ep := peer.GetEndpoint(); ep != nil {
		e.log.Debug("trying hole punch", "peer", peer.Hostname, "ep", ep)
		result, err := nat.HolePunch(e.ctx, e.udp, ep)
		if err == nil && result.Success {
			peer.SetEndpoint(result.Endpoint)
			e.log.Info("hole punch succeeded", "peer", peer.Hostname, "ep", result.Endpoint)
			return e.initiateHandshake(peer)
		}
		e.log.Debug("hole punch failed, falling back to DERP", "peer", peer.Hostname)
	}

	// Fallback: send handshake via DERP relay.
	e.derpMu.Lock()
	dc := e.derpClient
	e.derpMu.Unlock()
	if dc != nil {
		return e.initiateHandshake(peer)
	}

	e.log.Warn("no path to peer — waiting for DERP map", "peer", peer.Hostname)
	return nil
}

// ─── Local Unix socket API ───────────────────────────────────────────────────

// serveLocalAPI exposes a minimal JSON API on a Unix socket for CLI commands.
func (e *Engine) serveLocalAPI(ctx context.Context) {
	sockPath := e.cfg.DataDir + "/karadul.sock"
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		e.log.Warn("local api: listen failed", "err", err)
		return
	}
	defer ln.Close()
	defer os.Remove(sockPath)

	e.log.Debug("local api listening", "path", sockPath)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/status", e.handleAPIStatus)
	mux.HandleFunc("/peers", e.handleAPIPeers)
	mux.HandleFunc("/metrics", e.handleAPIMetrics)
	mux.HandleFunc("/exit-node/enable", e.handleAPIExitNodeEnable)
	mux.HandleFunc("/exit-node/use", e.handleAPIExitNodeUse)
	mux.HandleFunc("/shutdown", e.handleAPIShutdown)

	srv := &http.Server{Handler: mux}
	_ = srv.Serve(ln)
}

func (e *Engine) handleAPIStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(e.LocalStatus())
}

func (e *Engine) handleAPIPeers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	peers := e.manager.ListPeers()
	type peerInfo struct {
		Hostname  string `json:"hostname"`
		NodeID    string `json:"nodeId"`
		VirtualIP string `json:"virtualIp"`
		State     string `json:"state"`
		Endpoint  string `json:"endpoint,omitempty"`
	}
	result := make([]peerInfo, 0, len(peers))
	for _, p := range peers {
		ep := ""
		if addr := p.GetEndpoint(); addr != nil {
			ep = addr.String()
		}
		result = append(result, peerInfo{
			Hostname:  p.Hostname,
			NodeID:    p.NodeID,
			VirtualIP: p.VirtualIP.String(),
			State:     p.GetState().String(),
			Endpoint:  ep,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}

func (e *Engine) handleAPIExitNodeEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OutInterface string `json:"out_interface"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.OutInterface == "" {
		http.Error(w, "missing out_interface", http.StatusBadRequest)
		return
	}

	if err := e.EnableExitNode(req.OutInterface); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (e *Engine) handleAPIExitNodeUse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Peer string `json:"peer"` // hostname or virtual IP
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Peer == "" {
		http.Error(w, "missing peer", http.StatusBadRequest)
		return
	}

	// Look up peer by hostname first, then by VIP.
	var peer *mesh.Peer
	for _, p := range e.manager.ListPeers() {
		if p.Hostname == req.Peer {
			peer = p
			break
		}
		if p.VirtualIP.String() == req.Peer {
			peer = p
			break
		}
	}
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	if err := e.UseExitNode(peer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"peer":   peer.Hostname,
	})
}

func (e *Engine) handleAPIShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "shutting down"})
	if e.cancel != nil {
		e.cancel()
	}
}

// ─── Automatic key rotation ──────────────────────────────────────────────────

// rekeyLoop periodically checks each established session and triggers a new
// handshake whenever the session approaches its 2-minute lifetime.
func (e *Engine) rekeyLoop(ctx context.Context) {
	ticker := time.NewTicker(rekeyCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.mu.RLock()
			var toRekey []*peerSession
			for _, ps := range e.sessions {
				if ps.session.NeedsRekey() {
					toRekey = append(toRekey, ps)
				}
			}
			e.mu.RUnlock()

			for _, ps := range toRekey {
				if ps.peer != nil {
					e.log.Debug("session rekey", "peer", ps.peer.Hostname)
					e.RekeyPeer(ps.peer)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ─── Key rotation (manual) ───────────────────────────────────────────────────

// RekeyPeer forces a fresh handshake with peer (used for key rotation).
func (e *Engine) RekeyPeer(peer *mesh.Peer) {
	e.log.Debug("rekeying", "peer", peer.Hostname)
	// Remove old session so next packet triggers a fresh handshake.
	e.mu.Lock()
	delete(e.sessions, peer.PublicKey)
	e.mu.Unlock()
	go func() { _ = e.initiateHandshake(peer) }()
}

// ─── Exit node ───────────────────────────────────────────────────────────────

// EnableExitNode configures this node as an exit node.
// outIface is the LAN-facing interface (e.g. "eth0").
func (e *Engine) EnableExitNode(outIface string) error {
	if err := EnableExitNode(outIface); err != nil {
		return err
	}
	e.log.Info("exit node enabled", "out_iface", outIface)
	return nil
}

// UseExitNode routes all traffic through peer.
func (e *Engine) UseExitNode(peer *mesh.Peer) error {
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	if err := e.tun.AddRoute(defaultNet); err != nil {
		return fmt.Errorf("add default route: %w", err)
	}
	e.router.SetExitNode(peer)
	e.log.Info("using exit node", "peer", peer.Hostname)
	return nil
}

// ─── Status ──────────────────────────────────────────────────────────────────

// LocalStatus returns a JSON-serialisable summary of the node state.
func (e *Engine) LocalStatus() map[string]interface{} {
	e.mu.RLock()
	sessions := len(e.sessions)
	pending := len(e.pending)
	e.mu.RUnlock()

	peers := e.manager.ListPeers()
	peerInfo := make([]string, 0, len(peers))
	for _, p := range peers {
		peerInfo = append(peerInfo, mesh.PeerSummary(p))
	}

	ep := ""
	if pubEP := e.publicEP.Load(); pubEP != nil {
		ep = pubEP.String()
	}

	return map[string]interface{}{
		"nodeId":    e.nodeID,
		"virtualIp": e.virtualIP.String(),
		"publicKey": e.kp.Public.String(),
		"publicEp":  ep,
		"sessions":  sessions,
		"pendingHs": pending,
		"peers":     peerInfo,
	}
}

// handleAPIMetrics serves Prometheus-compatible text metrics.
func (e *Engine) handleAPIMetrics(w http.ResponseWriter, _ *http.Request) {
	e.mu.RLock()
	sessions := len(e.sessions)
	pending := len(e.pending)
	e.mu.RUnlock()

	peers := e.manager.ListPeers()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP karadul_peers_total Number of known mesh peers\n")
	fmt.Fprintf(w, "# TYPE karadul_peers_total gauge\n")
	fmt.Fprintf(w, "karadul_peers_total %d\n", len(peers))

	fmt.Fprintf(w, "# HELP karadul_sessions_active Active encrypted sessions\n")
	fmt.Fprintf(w, "# TYPE karadul_sessions_active gauge\n")
	fmt.Fprintf(w, "karadul_sessions_active %d\n", sessions)

	fmt.Fprintf(w, "# HELP karadul_handshakes_pending In-progress handshakes\n")
	fmt.Fprintf(w, "# TYPE karadul_handshakes_pending gauge\n")
	fmt.Fprintf(w, "karadul_handshakes_pending %d\n", pending)

	fmt.Fprintf(w, "# HELP karadul_packets_tx_total Packets sent\n")
	fmt.Fprintf(w, "# TYPE karadul_packets_tx_total counter\n")
	fmt.Fprintf(w, "karadul_packets_tx_total %d\n", e.metricPacketsTx.Load())

	fmt.Fprintf(w, "# HELP karadul_packets_rx_total Packets received\n")
	fmt.Fprintf(w, "# TYPE karadul_packets_rx_total counter\n")
	fmt.Fprintf(w, "karadul_packets_rx_total %d\n", e.metricPacketsRx.Load())

	fmt.Fprintf(w, "# HELP karadul_bytes_tx_total Bytes sent\n")
	fmt.Fprintf(w, "# TYPE karadul_bytes_tx_total counter\n")
	fmt.Fprintf(w, "karadul_bytes_tx_total %d\n", e.metricBytesTx.Load())

	fmt.Fprintf(w, "# HELP karadul_bytes_rx_total Bytes received\n")
	fmt.Fprintf(w, "# TYPE karadul_bytes_rx_total counter\n")
	fmt.Fprintf(w, "karadul_bytes_rx_total %d\n", e.metricBytesRx.Load())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// nextID returns a unique, monotonically increasing session ID.
func (e *Engine) nextID() uint32 {
	return e.idCounter.Add(1)
}

func pathName(addr *net.UDPAddr) string {
	if addr == nil {
		return "relay"
	}
	return "direct:" + addr.String()
}

// packetDstPort parses the destination port from an IPv4 or IPv6 packet.
// Returns 0 for non-TCP/UDP packets or if the packet is too short.
func packetDstPort(pkt []byte) uint16 {
	if len(pkt) < 1 {
		return 0
	}
	version := pkt[0] >> 4
	var hdrLen int
	var proto uint8
	switch version {
	case 4:
		if len(pkt) < 20 {
			return 0
		}
		hdrLen = int(pkt[0]&0x0f) * 4
		proto = pkt[9]
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		hdrLen = 40
		proto = pkt[6]
	default:
		return 0
	}
	if proto != 6 && proto != 17 { // TCP=6, UDP=17
		return 0
	}
	if len(pkt) < hdrLen+4 {
		return 0
	}
	return uint16(pkt[hdrLen+2])<<8 | uint16(pkt[hdrLen+3])
}

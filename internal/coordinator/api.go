package coordinator

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/karadul/karadul/internal/config"
)

// RegisterRequest is the body of POST /api/v1/register.
type RegisterRequest struct {
	PublicKey  string   `json:"publicKey"`
	Hostname   string   `json:"hostname"`
	AuthKey    string   `json:"authKey"`
	Routes     []string `json:"routes,omitempty"`
	IsExitNode bool     `json:"isExitNode,omitempty"`
}

// RegisterResponse is the response of POST /api/v1/register.
type RegisterResponse struct {
	NodeID    string `json:"nodeId"`
	VirtualIP string `json:"virtualIp"`
	Hostname  string `json:"hostname"`
}

// PollRequest is the body of POST /api/v1/poll.
type PollRequest struct {
	SinceVersion int64 `json:"sinceVersion"`
}

// UpdateEndpointRequest is the body of POST /api/v1/update-endpoint.
type UpdateEndpointRequest struct {
	Endpoint string `json:"endpoint"` // "ip:port"
	RxBytes  int64  `json:"rxBytes,omitempty"`
	TxBytes  int64  `json:"txBytes,omitempty"`
}

// API holds the HTTP handler dependencies.
type API struct {
	store        *Store
	pool         *IPPool
	poller       *Poller
	approvalMode string // "auto" or "manual"
	cfg          *config.ServerConfig
	startTime    time.Time
	cpuSampler   *cpuSampler
}

// Close releases resources held by the API.
func (a *API) Close() {
	if a.cpuSampler != nil {
		a.cpuSampler.Stop()
	}
}

// NewAPI creates an API handler set.
func NewAPI(store *Store, pool *IPPool, poller *Poller, approvalMode string, cfg *config.ServerConfig) *API {
	return &API{
		store:        store,
		pool:         pool,
		poller:       poller,
		approvalMode: approvalMode,
		cfg:          cfg,
		startTime:    time.Now(),
		cpuSampler:   newCPUSampler(5 * time.Second),
	}
}

// RegisterRoutes attaches all handlers to mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/register", a.handleRegister)
	mux.HandleFunc("/api/v1/poll", a.handlePoll)
	mux.HandleFunc("/api/v1/update-endpoint", a.handleUpdateEndpoint)
	mux.HandleFunc("/api/v1/exchange-endpoint", a.handleExchangeEndpoint)
	mux.HandleFunc("/api/v1/ping", a.handlePing)

	// Protected GET endpoints — require node HMAC signature or admin Bearer token
	// when admin_secret is configured. If no secret is set, access is open.
	protectedAuth := a.nodeOrAdminAuth()
	mux.Handle("/api/v1/peers", protectedAuth(http.HandlerFunc(a.handlePeers)))
	mux.Handle("/api/v1/derp-map", protectedAuth(http.HandlerFunc(a.handleDERPMap)))
	mux.Handle("/api/v1/topology", protectedAuth(http.HandlerFunc(a.handleTopology)))
	mux.Handle("/api/v1/status", protectedAuth(http.HandlerFunc(a.handleStatus)))

	// Admin routes protected by bearer token when admin_secret is configured.
	adminAuth := a.adminAuth()
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/api/v1/admin/nodes", a.handleAdminNodes)
	adminMux.HandleFunc("/api/v1/admin/nodes/", a.handleAdminNodes)
	adminMux.HandleFunc("/api/v1/admin/acl", a.handleAdminACL)
	adminMux.HandleFunc("/api/v1/admin/auth-keys", a.handleAdminAuthKeys)
	adminMux.HandleFunc("/api/v1/admin/auth-keys/", a.handleAdminAuthKeys)
	adminMux.HandleFunc("/api/v1/admin/config", a.handleAdminConfig)
	mux.Handle("/api/v1/admin/", adminAuth(adminMux))
}

// adminAuth returns middleware that requires a matching Bearer token for
// admin endpoints. If no admin_secret is configured, it is a no-op.
func (a *API) adminAuth() func(http.Handler) http.Handler {
	secret := ""
	if a.cfg != nil {
		secret = a.cfg.AdminSecret
	}
	return func(next http.Handler) http.Handler {
		if secret == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// nodeOrAdminAuth returns middleware that requires either a valid node HMAC
// signature (X-Karadul-Key + X-Karadul-Sig) or an admin Bearer token.
// If no admin_secret is configured, it is a no-op (backward compatible).
func (a *API) nodeOrAdminAuth() func(http.Handler) http.Handler {
	secret := ""
	if a.cfg != nil {
		secret = a.cfg.AdminSecret
	}
	return func(next http.Handler) http.Handler {
		if secret == "" {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try admin Bearer token.
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token := strings.TrimPrefix(auth, "Bearer ")
				if subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1 {
					next.ServeHTTP(w, r)
					return
				}
			}
			// Try node HMAC signature.
			if r.Header.Get(headerKey) != "" && r.Header.Get(headerSig) != "" {
				if err := VerifyRequestSignature(a.store, r, nil); err == nil {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		})
	}
}

// isValidID checks that s contains only safe characters (alphanumeric, hyphens).
func isValidID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
			return false
		}
	}
	return true
}

func isValidPublicKey(s string) bool {
	if s == "" {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	return len(b) == 32
}

// sanitizeHostname returns a cleaned hostname or rejects it.
func sanitizeHostname(s string) (string, error) {
	if len(s) > 253 {
		return "", fmt.Errorf("hostname too long (%d bytes)", len(s))
	}
	// Allow alphanumeric, hyphens, dots.
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return "", fmt.Errorf("hostname contains invalid character: %q", c)
		}
	}
	return s, nil
}

// handleRegister handles POST /api/v1/register.
func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// Validate public key.
	if !isValidPublicKey(req.PublicKey) {
		http.Error(w, "invalid public key: must be base64-encoded 32 bytes", http.StatusBadRequest)
		return
	}

	// Sanitize hostname if provided.
	if req.Hostname != "" {
		clean, err := sanitizeHostname(req.Hostname)
		if err != nil {
			http.Error(w, "invalid hostname: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Hostname = clean
	}

	// Validate auth key.
	ak, ok := a.store.GetAuthKey(req.AuthKey)
	if !ok {
		http.Error(w, "invalid auth key", http.StatusUnauthorized)
		return
	}
	if err := ValidateAuthKey(ak); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Determine status.
	status := NodeStatusActive
	if a.approvalMode == "manual" {
		status = NodeStatusPending
	}

	// Check if node already registered (re-registration).
	existing, exists := a.store.GetNodeByPubKey(req.PublicKey)
	if exists {
		// Update and return.
		if err := a.store.UpdateNode(existing.ID, func(n *Node) {
			if req.Hostname != "" {
				n.Hostname = req.Hostname
			}
			n.Routes = req.Routes
			n.IsExitNode = req.IsExitNode
			n.LastSeen = time.Now()
		}); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, RegisterResponse{
			NodeID:    existing.ID,
			VirtualIP: existing.VirtualIP,
			Hostname:  existing.Hostname,
		})
		return
	}

	// Allocate virtual IP.
	nodeID := generateID()
	vip, err := a.pool.Allocate(nodeID)
	if err != nil {
		http.Error(w, "ip pool exhausted", http.StatusServiceUnavailable)
		return
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = fmt.Sprintf("node-%s", nodeID[:8])
	}

	node := &Node{
		ID:           nodeID,
		PublicKey:    req.PublicKey,
		Hostname:     hostname,
		VirtualIP:    vip.String(),
		Status:       status,
		AuthKeyID:    ak.ID,
		Routes:       req.Routes,
		IsExitNode:   req.IsExitNode,
		RegisteredAt: time.Now(),
		LastSeen:     time.Now(),
	}

	if err := a.store.AddNode(node); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	// Mark ephemeral key used.
	if ak.Ephemeral {
		if err := a.store.MarkAuthKeyUsed(ak.ID); err != nil {
			log.Printf("warn: mark auth key used: %v", err)
		}
	}

	writeJSON(w, RegisterResponse{
		NodeID:    nodeID,
		VirtualIP: vip.String(),
		Hostname:  hostname,
	})
}

// handlePoll handles POST /api/v1/poll (long-poll for state updates).
func (a *API) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req PollRequest
	// Body is optional; proceed with defaults if empty/bad JSON.
	_ = json.Unmarshal(body, &req)

	// Verify auth.
	if err := VerifyRequestSignature(a.store, r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	state := a.poller.WaitForUpdate(r.Context(), req.SinceVersion)
	writeJSON(w, state)
}

// handleUpdateEndpoint handles POST /api/v1/update-endpoint.
func (a *API) handleUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if err := VerifyRequestSignature(a.store, r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req UpdateEndpointRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	pubKey := r.Header.Get(headerKey)
	node, ok := a.store.GetNodeByPubKey(pubKey)
	if !ok {
		http.Error(w, "unknown node", http.StatusUnauthorized)
		return
	}

	if err := a.store.UpdateNode(node.ID, func(n *Node) {
		n.Endpoint = req.Endpoint
		n.LastSeen = time.Now()
		n.RxBytes = req.RxBytes
		n.TxBytes = req.TxBytes
	}); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// PeerResponse is the frontend-facing peer representation returned by GET /api/v1/peers.
type PeerResponse struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	VirtualIP     string `json:"virtualIP"`
	State         string `json:"state"` // Direct, Relayed, Idle, Discovered
	Endpoint      string `json:"endpoint,omitempty"`
	Latency       int    `json:"latency,omitempty"` // ms
	RxBytes       int64  `json:"rxBytes"`
	TxBytes       int64  `json:"txBytes"`
	LastHandshake string `json:"lastHandshake,omitempty"`
	PublicKey     string `json:"publicKey,omitempty"`
}

// handlePeers handles GET /api/v1/peers.
func (a *API) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodes := a.store.ListNodes()
	now := time.Now()
	recentThreshold := 5 * time.Minute

	peers := make([]PeerResponse, 0, len(nodes))
	for _, n := range nodes {
		if n.Status != NodeStatusActive {
			continue
		}

		// Determine peer connection state.
		state := "Idle"
		hasEndpoint := n.Endpoint != ""
		isRecent := !n.LastSeen.IsZero() && now.Sub(n.LastSeen) < recentThreshold

		if hasEndpoint && isRecent {
			state = "Direct"
		} else if isRecent {
			state = "Relayed"
		} else if hasEndpoint {
			state = "Discovered"
		}

		peers = append(peers, PeerResponse{
			ID:            n.ID,
			Hostname:      n.Hostname,
			VirtualIP:     n.VirtualIP,
			State:         state,
			Endpoint:      n.Endpoint,
			RxBytes:       n.RxBytes,
			TxBytes:       n.TxBytes,
			LastHandshake: n.LastSeen.Format(time.RFC3339),
			PublicKey:     n.PublicKey,
		})
	}
	writeJSON(w, peers)
}

// handleDERPMap handles GET /api/v1/derp-map.
func (a *API) handleDERPMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, a.buildDERPMap())
}

// buildDERPMap constructs the DERPMap from the current configuration.
func (a *API) buildDERPMap() *DERPMap {
	regions := []*DERPRegion{}

	if a.cfg == nil || !a.cfg.DERP.Enabled {
		return &DERPMap{Regions: regions}
	}

	// Determine DERP address from config, falling back to the coordinator address.
	derpAddr := a.cfg.DERP.Addr
	if derpAddr == "" {
		derpAddr = a.cfg.Addr
	}

	// Extract the host and port.
	host, port := parseDERPAddr(derpAddr)

	regions = append(regions, &DERPRegion{
		RegionID:   1,
		RegionCode: "default",
		RegionName: "Default Relay",
		Nodes: []*DERPNode{{
			Name:     "default-relay",
			RegionID: 1,
			HostName: host,
			DERPPort: port,
		}},
	})

	return &DERPMap{Regions: regions}
}

// handlePing handles POST /api/v1/ping (keepalive / endpoint exchange).
func (a *API) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if err := VerifyRequestSignature(a.store, r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	pubKey := r.Header.Get(headerKey)
	if node, ok := a.store.GetNodeByPubKey(pubKey); ok {
		if err := a.store.UpdateNode(node.ID, func(n *Node) {
			n.LastSeen = time.Now()
		}); err != nil {
			log.Printf("warn: ping update lastSeen: %v", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleAdminNodes handles GET/DELETE /api/v1/admin/nodes and
// POST /api/v1/admin/nodes/{id}/approve.
func (a *API) handleAdminNodes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// POST /api/v1/admin/nodes/{id}/approve — approve a pending node.
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/approve") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/admin/nodes/"), "/approve")
		if id == "" || !isValidID(id) {
			http.Error(w, "invalid node id", http.StatusBadRequest)
			return
		}
		if err := a.store.UpdateNode(id, func(n *Node) {
			n.Status = NodeStatusActive
		}); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListNodes())
	case http.MethodDelete:
		// DELETE /api/v1/admin/nodes/{id}
		id := strings.TrimPrefix(path, "/api/v1/admin/nodes/")
		if id == "" || !isValidID(id) {
			http.Error(w, "invalid node id", http.StatusBadRequest)
			return
		}
		if err := a.store.DeleteNode(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminACL handles GET/PUT /api/v1/admin/acl.
func (a *API) handleAdminACL(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.GetACL())
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var acl ACLPolicy
		if err := json.Unmarshal(body, &acl); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := a.store.SetACL(acl); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ExchangeEndpointRequest is the body of POST /api/v1/exchange-endpoint.
// Used for hole punch coordination: a node tells the server "I want to reach
// targetPubKey; here is my current endpoint". The server stores it and
// signals the target via the poll mechanism.
type ExchangeEndpointRequest struct {
	TargetPubKey string `json:"targetPubKey"`
	MyEndpoint   string `json:"myEndpoint"` // "ip:port" as seen by us
}

// ExchangeEndpointResponse returns the target's last-known endpoint.
type ExchangeEndpointResponse struct {
	TargetEndpoint string `json:"targetEndpoint"`
}

// handleExchangeEndpoint handles POST /api/v1/exchange-endpoint.
func (a *API) handleExchangeEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if err := VerifyRequestSignature(a.store, r, body); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var req ExchangeEndpointRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// Update caller's endpoint.
	callerPubKey := r.Header.Get(headerKey)
	if callerNode, ok := a.store.GetNodeByPubKey(callerPubKey); ok {
		if req.MyEndpoint != "" {
			if err := a.store.UpdateNode(callerNode.ID, func(n *Node) {
				n.Endpoint = req.MyEndpoint
				n.LastSeen = time.Now()
			}); err != nil {
				log.Printf("warn: exchange-endpoint update caller: %v", err)
			}
		}
	}

	// Return target's current endpoint (if known).
	targetNode, ok := a.store.GetNodeByPubKey(req.TargetPubKey)
	if !ok {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}
	writeJSON(w, ExchangeEndpointResponse{TargetEndpoint: targetNode.Endpoint})
}

// CreateAuthKeyRequest is the body of POST /api/v1/admin/auth-keys.
type CreateAuthKeyRequest struct {
	Ephemeral bool   `json:"ephemeral"`
	ExpiryTTL string `json:"expiry"` // Go duration string, e.g. "24h". Empty = no expiry.
}

// handleAdminAuthKeys handles GET/POST /api/v1/admin/auth-keys and
// DELETE /api/v1/admin/auth-keys/{id}.
func (a *API) handleAdminAuthKeys(w http.ResponseWriter, r *http.Request) {
	// DELETE /api/v1/admin/auth-keys/{id}
	if r.Method == http.MethodDelete {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/auth-keys/")
		if id == "" || !isValidID(id) {
			http.Error(w, "invalid key id", http.StatusBadRequest)
			return
		}
		if err := a.store.DeleteAuthKey(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.store.ListAuthKeys())
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req CreateAuthKeyRequest
		// Body is optional; proceed with defaults if empty / bad JSON.
		_ = json.Unmarshal(body, &req)

		var ttl time.Duration
		if req.ExpiryTTL != "" {
			var err error
			ttl, err = time.ParseDuration(req.ExpiryTTL)
			if err != nil {
				http.Error(w, "invalid expiry duration: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		ak, err := GenerateAuthKey(req.Ephemeral, ttl)
		if err != nil {
			http.Error(w, "generate key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.store.AddAuthKey(ak); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ak)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// readBody reads up to maxBytes from r.Body. Returns an error on failure.
func readBody(r *http.Request, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	data = append(data, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("karadul: crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// parseDERPAddr splits an address (e.g. ":8080" or "127.0.0.1:3340") into host and port.
// If the host is empty (e.g. ":8080"), it defaults to "127.0.0.1".
func parseDERPAddr(addr string) (host string, port int) {
	host = "127.0.0.1"
	port = 443

	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	if h != "" {
		host = h
	}
	port, _ = strconv.Atoi(p)
	if port == 0 {
		port = 443
	}
	return
}

// TopologyConnection represents a connection between two nodes in the mesh
type TopologyConnection struct {
	From    string  `json:"from"`
	To      string  `json:"to"`
	Type    string  `json:"type"` // "direct" or "relay"
	Latency float64 `json:"latency,omitempty"`
}

// TopologyResponse represents the mesh topology
type TopologyResponse struct {
	Nodes       []*Node              `json:"nodes"`
	Connections []TopologyConnection `json:"connections"`
}

// handleTopology handles GET /api/v1/topology.
func (a *API) handleTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes := a.store.ListNodes()
	now := time.Now()
	recentThreshold := 5 * time.Minute

	// Collect recently-seen active nodes.
	type activeNode struct {
		*Node
		recent bool
	}
	var active []*activeNode
	for _, n := range nodes {
		if n.Status != NodeStatusActive {
			continue
		}
		recent := !n.LastSeen.IsZero() && now.Sub(n.LastSeen) < recentThreshold
		active = append(active, &activeNode{Node: n, recent: recent})
	}

	// Build connections only between nodes that have been seen recently
	// and have either exchanged endpoints or communicated.
	var connections []TopologyConnection
	for i, n1 := range active {
		if !n1.recent {
			continue
		}
		for j, n2 := range active {
			if i >= j || !n2.recent {
				continue
			}
			// Determine connection type based on endpoint availability.
			// Nodes that have both discovered each other's endpoints can
			// communicate directly; otherwise they must relay through the
			// coordinator.
			connType := "relay"
			if n1.Endpoint != "" && n2.Endpoint != "" {
				connType = "direct"
			}
			connections = append(connections, TopologyConnection{
				From: n1.ID,
				To:   n2.ID,
				Type: connType,
			})
		}
	}

	writeJSON(w, TopologyResponse{
		Nodes:       nodes,
		Connections: connections,
	})
}

// SystemStatus represents the current system status
type SystemStatus struct {
	Uptime         int64   `json:"uptime"`
	MemoryUsage    int64   `json:"memoryUsage"`
	CPUUsage       float64 `json:"cpuUsage"`
	Goroutines     int     `json:"goroutines"`
	PeersConnected int     `json:"peersConnected"`
	TotalRx        int64   `json:"totalRx"`
	TotalTx        int64   `json:"totalTx"`
}

// handleStatus handles GET /api/v1/status.
func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes := a.store.ListNodes()
	activeCount := 0
	var totalRx, totalTx int64
	for _, n := range nodes {
		if n.Status == NodeStatusActive {
			activeCount++
		}
		totalRx += n.RxBytes
		totalTx += n.TxBytes
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := SystemStatus{
		Uptime:         int64(time.Since(a.startTime).Seconds()),
		MemoryUsage:    int64(memStats.Sys),
		CPUUsage:       a.cpuSampler.CPUUsage(),
		Goroutines:     runtime.NumGoroutine(),
		PeersConnected: activeCount,
		TotalRx:        totalRx,
		TotalTx:        totalTx,
	}

	writeJSON(w, status)
}

// handleAdminConfig handles GET/PUT /api/v1/admin/config.
func (a *API) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, a.cfg)
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var cfg config.ServerConfig
		if err := json.Unmarshal(body, &cfg); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		// Preserve TLS config from existing if not provided in update.
		if cfg.TLS == (config.TLSConfig{}) {
			cfg.TLS = a.cfg.TLS
		}
		if err := config.ValidateServerConfig(&cfg); err != nil {
			http.Error(w, "invalid config: "+err.Error(), http.StatusBadRequest)
			return
		}
		*a.cfg = cfg
		// Persist config to disk.
		if a.cfg.DataDir != "" {
			configPath := a.cfg.DataDir + "/config.json"
			if err := config.SaveServerConfig(a.cfg, configPath); err != nil {
				log.Printf("warn: admin config save failed: %v", err)
			}
		}
		writeJSON(w, cfg)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

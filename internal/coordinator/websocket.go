package coordinator

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Hub manages WebSocket connections and broadcasts messages
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	store      *Store
	mu         sync.RWMutex
	startTime  time.Time
}

// Client represents a WebSocket client
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

// NewHub creates a new WebSocket hub
func NewHub(store *Store) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		store:      store,
		startTime:  time.Now(),
	}
}

// Run starts the hub's event loop
func (h *Hub) Run() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

			// Send initial state
			h.sendInitialState(client)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()

		case <-ticker.C:
			// Broadcast periodic updates
			h.broadcastUpdate()
		}
	}
}

// sendInitialState sends the current state to a newly connected client
func (h *Hub) sendInitialState(client *Client) {
	nodes := h.store.ListNodes()

	// Send nodes
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "nodes",
		"data": nodes,
	}); err == nil {
		select {
		case client.send <- msg:
		default:
		}
	}

	// Send peers (active nodes as peer-like objects)
	peers := buildPeersFromNodes(nodes)
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "peers",
		"data": peers,
	}); err == nil {
		select {
		case client.send <- msg:
		default:
		}
	}

	// Send topology
	topology := buildTopologyFromNodes(nodes)
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "topology",
		"data": topology,
	}); err == nil {
		select {
		case client.send <- msg:
		default:
		}
	}

	// Send stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := SystemStatus{
		Uptime:         int64(time.Since(h.startTime).Seconds()),
		MemoryUsage:    int64(memStats.Sys),
		CPUUsage:       0,
		Goroutines:     runtime.NumGoroutine(),
		PeersConnected: 0,
		TotalRx:        0,
		TotalTx:        0,
	}
	for _, n := range nodes {
		if n.Status == NodeStatusActive {
			status.PeersConnected++
		}
	}
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "stats",
		"data": status,
	}); err == nil {
		select {
		case client.send <- msg:
		default:
		}
	}
}

// broadcastUpdate broadcasts the current state to all clients
func (h *Hub) broadcastUpdate() {
	nodes := h.store.ListNodes()

	// Broadcast nodes
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "nodes",
		"data": nodes,
	}); err == nil {
		h.broadcast <- msg
	}

	// Broadcast peers
	peers := buildPeersFromNodes(nodes)
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "peers",
		"data": peers,
	}); err == nil {
		h.broadcast <- msg
	}

	// Broadcast topology
	topology := buildTopologyFromNodes(nodes)
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "topology",
		"data": topology,
	}); err == nil {
		h.broadcast <- msg
	}

	// Broadcast stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := SystemStatus{
		Uptime:         int64(time.Since(h.startTime).Seconds()),
		MemoryUsage:    int64(memStats.Sys),
		CPUUsage:       0,
		Goroutines:     runtime.NumGoroutine(),
		PeersConnected: 0,
		TotalRx:        0,
		TotalTx:        0,
	}
	for _, n := range nodes {
		if n.Status == NodeStatusActive {
			status.PeersConnected++
		}
	}
	if msg, err := json.Marshal(map[string]interface{}{
		"type": "stats",
		"data": status,
	}); err == nil {
		h.broadcast <- msg
	}
}

// buildPeersFromNodes converts active nodes into PeerResponse objects for WebSocket broadcast.
func buildPeersFromNodes(nodes []*Node) []PeerResponse {
	now := time.Now()
	recentThreshold := 5 * time.Minute
	peers := make([]PeerResponse, 0, len(nodes))
	for _, n := range nodes {
		if n.Status != NodeStatusActive {
			continue
		}
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
	return peers
}

// buildTopologyFromNodes builds a topology response from node data.
func buildTopologyFromNodes(nodes []*Node) map[string]interface{} {
	now := time.Now()
	recentThreshold := 5 * time.Minute

	type topoNode struct {
		*Node
		recent bool
	}
	var active []*topoNode
	for _, n := range nodes {
		if n.Status != NodeStatusActive {
			continue
		}
		recent := !n.LastSeen.IsZero() && now.Sub(n.LastSeen) < recentThreshold
		active = append(active, &topoNode{Node: n, recent: recent})
	}

	var connections []TopologyConnection
	for i, n1 := range active {
		if !n1.recent {
			continue
		}
		for j, n2 := range active {
			if i >= j || !n2.recent {
				continue
			}
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

	return map[string]interface{}{
		"nodes":       nodes,
		"connections": connections,
	}
}

// ServeWS handles WebSocket connections
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}
	client.hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				// Log unexpected close
			}
			break
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current WebSocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

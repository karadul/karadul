package coordinator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NodeStatus tracks the lifecycle state of a registered node.
type NodeStatus string

const (
	NodeStatusPending  NodeStatus = "pending"
	NodeStatusActive   NodeStatus = "online"
	NodeStatusDisabled NodeStatus = "offline"
)

// Node represents a registered mesh node.
type Node struct {
	ID           string     `json:"id"`
	PublicKey    string     `json:"publicKey"` // base64 X25519 public key
	Hostname     string     `json:"hostname"`
	VirtualIP    string     `json:"virtualIP"` // e.g. "100.64.0.2"
	Endpoint     string     `json:"endpoint"`  // last known UDP endpoint "ip:port"
	Status       NodeStatus `json:"status"`
	AuthKeyID    string     `json:"authKeyId,omitempty"`
	Routes       []string   `json:"routes,omitempty"`
	IsExitNode   bool       `json:"isExitNode,omitempty"`
	RegisteredAt time.Time  `json:"registeredAt"`
	LastSeen     time.Time  `json:"lastSeen"`
}

// AuthKey is a pre-shared key that allows a node to register.
type AuthKey struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`       // random secret the node presents
	Ephemeral bool      `json:"ephemeral"` // single-use key
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	Used      bool      `json:"used"`
}

// ACLPolicy is the network access control policy.
type ACLPolicy struct {
	Version int       `json:"version"`
	Rules   []ACLRule `json:"rules"`
}

// ACLRule describes a single allow/deny rule.
type ACLRule struct {
	Action string   `json:"action"` // "allow" or "deny"
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Ports  []string `json:"ports,omitempty"`
}

// State is the complete coordinator state serialised to disk.
type State struct {
	Version   int        `json:"version"`
	Nodes     []*Node    `json:"nodes"`
	AuthKeys  []*AuthKey `json:"auth_keys"`
	ACL       ACLPolicy  `json:"acl"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Store is a thread-safe in-memory state store backed by a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	state   State
	version int64 // monotonically increasing; poll subscribers watch this

	subscribers []chan struct{}
	subMu       sync.Mutex
}

// NewStore creates a Store backed by path.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load state: %w", err)
	}
	return s, nil
}

// Load reads state from the JSON file.
func (s *Store) Load() error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	s.mu.Lock()
	defer s.mu.Unlock()
	return json.NewDecoder(f).Decode(&s.state)
}

// Save writes state to the JSON file atomically (write to tmp, rename).
func (s *Store) Save() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.state, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, s.path)
}

// notify wakes all poll subscribers.
func (s *Store) notify() {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// subscribe returns a channel that receives a signal when state changes.
func (s *Store) subscribe() (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.subMu.Lock()
	s.subscribers = append(s.subscribers, ch)
	s.subMu.Unlock()

	cancel := func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		for i, c := range s.subscribers {
			if c == ch {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				return
			}
		}
	}
	return ch, cancel
}

// --- Node operations ---

// GetNode returns the node with the given ID.
func (s *Store) GetNode(id string) (*Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.state.Nodes {
		if n.ID == id {
			cp := *n
			return &cp, true
		}
	}
	return nil, false
}

// GetNodeByPubKey returns the node with the given public key.
func (s *Store) GetNodeByPubKey(pubKey string) (*Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.state.Nodes {
		if n.PublicKey == pubKey {
			cp := *n
			return &cp, true
		}
	}
	return nil, false
}

// AddNode adds or replaces a node. Triggers state change notification.
func (s *Store) AddNode(n *Node) error {
	s.mu.Lock()
	for i, existing := range s.state.Nodes {
		if existing.ID == n.ID {
			s.state.Nodes[i] = n
			s.state.UpdatedAt = time.Now()
			s.version++
			s.mu.Unlock()
			s.notify()
			return s.Save()
		}
	}
	s.state.Nodes = append(s.state.Nodes, n)
	s.state.UpdatedAt = time.Now()
	s.version++
	s.mu.Unlock()
	s.notify()
	return s.Save()
}

// UpdateNode applies a mutation function to a node by ID.
func (s *Store) UpdateNode(id string, fn func(*Node)) error {
	s.mu.Lock()
	for _, n := range s.state.Nodes {
		if n.ID == id {
			fn(n)
			s.state.UpdatedAt = time.Now()
			s.mu.Unlock()
			s.notify()
			return s.Save()
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("node %s not found", id)
}

// DeleteNode removes a node by ID.
func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	for i, n := range s.state.Nodes {
		if n.ID == id {
			s.state.Nodes = append(s.state.Nodes[:i], s.state.Nodes[i+1:]...)
			s.state.UpdatedAt = time.Now()
			s.mu.Unlock()
			s.notify()
			return s.Save()
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("node %s not found", id)
}

// ListNodes returns a snapshot of all nodes.
func (s *Store) ListNodes() []*Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Node, len(s.state.Nodes))
	for i, n := range s.state.Nodes {
		cp := *n
		result[i] = &cp
	}
	return result
}

// --- AuthKey operations ---

// GetAuthKey returns an auth key by its secret.
func (s *Store) GetAuthKey(secret string) (*AuthKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.state.AuthKeys {
		if k.Key == secret {
			cp := *k
			return &cp, true
		}
	}
	return nil, false
}

// AddAuthKey persists a new auth key.
func (s *Store) AddAuthKey(k *AuthKey) error {
	s.mu.Lock()
	s.state.AuthKeys = append(s.state.AuthKeys, k)
	s.mu.Unlock()
	return s.Save()
}

// MarkAuthKeyUsed marks an ephemeral key as used.
func (s *Store) MarkAuthKeyUsed(id string) error {
	s.mu.Lock()
	for _, k := range s.state.AuthKeys {
		if k.ID == id {
			k.Used = true
			k.UsedAt = time.Now()
			s.mu.Unlock()
			return s.Save()
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("auth key %s not found", id)
}

// DeleteAuthKey removes an auth key by ID.
func (s *Store) DeleteAuthKey(id string) error {
	s.mu.Lock()
	keys := s.state.AuthKeys
	for i, k := range keys {
		if k.ID == id {
			s.state.AuthKeys = append(keys[:i], keys[i+1:]...)
			s.mu.Unlock()
			return s.Save()
		}
	}
	s.mu.Unlock()
	return fmt.Errorf("auth key %s not found", id)
}

// ListAuthKeys returns all auth keys.
func (s *Store) ListAuthKeys() []*AuthKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*AuthKey, len(s.state.AuthKeys))
	for i, k := range s.state.AuthKeys {
		cp := *k
		result[i] = &cp
	}
	return result
}

// --- ACL ---

// GetACL returns the current ACL policy.
func (s *Store) GetACL() ACLPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.ACL
}

// SetACL replaces the ACL policy.
func (s *Store) SetACL(acl ACLPolicy) error {
	s.mu.Lock()
	s.state.ACL = acl
	s.state.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.notify()
	return s.Save()
}

// Version returns the current state version (number of mutations since start).
func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// UpdatedAt returns the timestamp of the last state change.
func (s *Store) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.UpdatedAt
}

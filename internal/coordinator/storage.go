package coordinator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	RxBytes      int64      `json:"rxBytes"`
	TxBytes      int64      `json:"txBytes"`
}

// AuthKey is a pre-shared key that allows a node to register.
type AuthKey struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`       // random secret the node presents
	Ephemeral bool      `json:"ephemeral"` // single-use key
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	UsedAt    time.Time `json:"usedAt,omitempty"`
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
	AuthKeys  []*AuthKey `json:"authKeys"`
	ACL       ACLPolicy  `json:"acl"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// StateFile is the on-disk format that includes the mutation version counter.
type StateFile struct {
	State
	MutationVersion int64 `json:"mutationVersion"`
}

// Store is a thread-safe in-memory state store backed by a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	state   State
	version int64 // monotonically increasing; poll subscribers watch this

	subscribers []chan struct{}
	subMu       sync.Mutex

	// GC state
	gcDone chan struct{}
	gcStop chan struct{}
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
	var sf StateFile
	if err := json.NewDecoder(f).Decode(&sf); err != nil {
		return err
	}
	s.state = sf.State
	s.version = sf.MutationVersion
	return nil
}

// Save writes state to the JSON file atomically (write to tmp, rename).
// Caller must NOT hold s.mu — this method acquires the write lock for the
// full serialize + write cycle to prevent concurrent mutations from
// producing an inconsistent on-disk snapshot.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// saveLocked writes state to disk. Must be called with s.mu held.
func (s *Store) saveLocked() error {
	sf := StateFile{
		State:           s.state,
		MutationVersion: s.version,
	}
	data, err := json.MarshalIndent(sf, "", "  ")
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
	defer s.mu.Unlock()
	for i, existing := range s.state.Nodes {
		if existing.ID == n.ID {
			s.state.Nodes[i] = n
			s.state.UpdatedAt = time.Now()
			s.version++
			s.notify()
			return s.saveLocked()
		}
	}
	s.state.Nodes = append(s.state.Nodes, n)
	s.state.UpdatedAt = time.Now()
	s.version++
	s.notify()
	return s.saveLocked()
}

// UpdateNode applies a mutation function to a node by ID.
func (s *Store) UpdateNode(id string, fn func(*Node)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.state.Nodes {
		if n.ID == id {
			fn(n)
			s.state.UpdatedAt = time.Now()
			s.notify()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("node %s not found", id)
}

// DeleteNode removes a node by ID.
func (s *Store) DeleteNode(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.state.Nodes {
		if n.ID == id {
			s.state.Nodes = append(s.state.Nodes[:i], s.state.Nodes[i+1:]...)
			s.state.UpdatedAt = time.Now()
			s.notify()
			return s.saveLocked()
		}
	}
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
	defer s.mu.Unlock()
	s.state.AuthKeys = append(s.state.AuthKeys, k)
	return s.saveLocked()
}

// MarkAuthKeyUsed marks an ephemeral key as used.
func (s *Store) MarkAuthKeyUsed(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.state.AuthKeys {
		if k.ID == id {
			k.Used = true
			k.UsedAt = time.Now()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("auth key %s not found", id)
}

// DeleteAuthKey removes an auth key by ID.
func (s *Store) DeleteAuthKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := s.state.AuthKeys
	for i, k := range keys {
		if k.ID == id {
			s.state.AuthKeys = append(keys[:i], keys[i+1:]...)
			return s.saveLocked()
		}
	}
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
	defer s.mu.Unlock()
	s.state.ACL = acl
	s.state.UpdatedAt = time.Now()
	s.notify()
	return s.saveLocked()
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

// --- Garbage collection ---

const (
	gcInterval        = 5 * time.Minute
	gcNodeStaleAge    = 30 * time.Minute // mark offline after 30 min inactivity
	gcNodeExpireAge   = 24 * time.Hour   // delete offline nodes after 24 h
	gcEphemeralKeyAge = 1 * time.Hour    // delete used ephemeral keys after 1 h
	gcKeyExpireAge    = 24 * time.Hour   // delete expired non-ephemeral keys after 24 h
)

// testGCInterval overrides gcInterval for tests. When non-nil, gcLoop uses this value.
var testGCInterval atomic.Pointer[time.Duration]

func init() {
	d := gcInterval
	testGCInterval.Store(&d)
}

// StartGC begins the background garbage-collection loop.
func (s *Store) StartGC() {
	s.gcDone = make(chan struct{})
	s.gcStop = make(chan struct{})
	go s.gcLoop()
}

// StopGC stops the background GC loop and waits for it to finish.
// Safe to call multiple times.
func (s *Store) StopGC() {
	if s.gcStop == nil {
		return
	}
	close(s.gcStop)
	<-s.gcDone
	s.gcStop = nil
}

func (s *Store) gcLoop() {
	defer close(s.gcDone)
	d := gcInterval
	if v := testGCInterval.Load(); v != nil {
		d = *v
	}
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.runGC()
		case <-s.gcStop:
			return
		}
	}
}

func (s *Store) runGC() {
	now := time.Now()
	dirty := false

	s.mu.Lock()
	defer func() {
		if dirty {
			s.state.UpdatedAt = now
			s.version++
			s.notify()
			if err := s.saveLocked(); err != nil {
				// Log but don't block GC on disk write failures.
				// The in-memory state is still consistent.
				fmt.Fprintf(os.Stderr, "karadul: gc save error: %v\n", err)
			}
		}
		s.mu.Unlock()
	}()

	// Phase 1: mark stale nodes offline.
	for _, n := range s.state.Nodes {
		if n.Status == NodeStatusActive && !n.LastSeen.IsZero() && now.Sub(n.LastSeen) > gcNodeStaleAge {
			n.Status = NodeStatusDisabled
			dirty = true
		}
	}

	// Phase 2: delete long-offline nodes.
	kept := s.state.Nodes[:0]
	for _, n := range s.state.Nodes {
		if n.Status == NodeStatusDisabled && !n.LastSeen.IsZero() && now.Sub(n.LastSeen) > gcNodeExpireAge {
			continue // drop
		}
		kept = append(kept, n)
	}
	if len(kept) != len(s.state.Nodes) {
		s.state.Nodes = kept
		dirty = true
	}

	// Phase 3: prune expired/used auth keys.
	keys := s.state.AuthKeys[:0]
	for _, k := range s.state.AuthKeys {
		if k.Ephemeral && k.Used && !k.UsedAt.IsZero() && now.Sub(k.UsedAt) > gcEphemeralKeyAge {
			continue // drop used ephemeral keys older than 1 h
		}
		if !k.Ephemeral && !k.ExpiresAt.IsZero() && now.After(k.ExpiresAt) && now.Sub(k.ExpiresAt) > gcKeyExpireAge {
			continue // drop expired non-ephemeral keys older than 24 h
		}
		keys = append(keys, k)
	}
	if len(keys) != len(s.state.AuthKeys) {
		s.state.AuthKeys = keys
		dirty = true
	}
}

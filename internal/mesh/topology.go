package mesh

import (
	"encoding/base64"
	"net"
	"strings"

	"github.com/karadul/karadul/internal/coordinator"
	klog "github.com/karadul/karadul/internal/log"
)

// TopologyManager applies NetworkState updates from the coordination server to the peer manager.
type TopologyManager struct {
	manager *Manager
	selfKey [32]byte // our own public key — exclude from peer list
	log     *klog.Logger
}

// NewTopologyManager creates a TopologyManager.
func NewTopologyManager(manager *Manager, selfKey [32]byte, log *klog.Logger) *TopologyManager {
	return &TopologyManager{
		manager: manager,
		selfKey: selfKey,
		log:     log,
	}
}

// Apply processes a NetworkState update from the coordination server.
// It adds new peers, updates existing ones, and marks removed ones as expired.
func (t *TopologyManager) Apply(state coordinator.NetworkState) {
	seen := make(map[[32]byte]bool)

	for _, node := range state.Nodes {
		if node.Status != coordinator.NodeStatusActive {
			continue
		}

		pubKey, err := keyFromBase64(node.PublicKey)
		if err != nil {
			t.log.Debug("topology: bad public key", "node", node.ID, "err", err)
			continue
		}

		// Skip ourselves.
		if pubKey == t.selfKey {
			continue
		}
		seen[pubKey] = true

		vip := net.ParseIP(node.VirtualIP)
		if vip == nil {
			continue
		}

		t.manager.AddOrUpdate(
			pubKey,
			node.Hostname,
			node.ID,
			vip,
			node.Endpoint,
			node.Routes,
		)
	}

	// Expire peers no longer in the topology.
	for _, p := range t.manager.ListPeers() {
		if !seen[p.PublicKey] {
			t.manager.Remove(p.PublicKey)
		}
	}
}

// keyFromBase64 decodes a base64 string into a [32]byte key.
func keyFromBase64(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, &keyLenError{len(b)}
	}
	copy(k[:], b)
	return k, nil
}

type keyLenError struct{ n int }

func (e *keyLenError) Error() string {
	return "key must be 32 bytes"
}

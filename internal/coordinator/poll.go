package coordinator

import (
	"context"
	"time"
)

const (
	// pollMaxWait is the maximum time a long-poll request will block.
	pollMaxWait = 30 * time.Second
)

// NetworkState is the snapshot sent to nodes during a poll response.
type NetworkState struct {
	Version   int64     `json:"version"`
	UpdatedAt string    `json:"updatedAt"`
	Nodes     []*Node   `json:"nodes"`
	ACL       ACLPolicy `json:"acl"`
	DERPMap   *DERPMap  `json:"derpMap,omitempty"`
}

// DERPMap lists available DERP relay servers.
type DERPMap struct {
	Regions []*DERPRegion `json:"regions"`
}

// DERPRegion is a named group of DERP relay nodes.
type DERPRegion struct {
	RegionID   int         `json:"regionId"`
	RegionCode string      `json:"regionCode"`
	RegionName string      `json:"regionName"`
	Nodes      []*DERPNode `json:"nodes"`
}

// DERPNode describes a single DERP relay endpoint.
type DERPNode struct {
	Name     string `json:"name"`
	RegionID int    `json:"regionId"`
	HostName string `json:"hostName"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	DERPPort int    `json:"derpPort"`
}

// Poller manages long-poll subscriptions.
type Poller struct {
	store   *Store
	derpMap func() *DERPMap // returns the current DERP map; may be nil
}

// NewPoller creates a Poller backed by store.
func NewPoller(store *Store) *Poller {
	return &Poller{store: store}
}

// SetDERPMapFn sets the function used to produce a DERPMap for poll responses.
func (p *Poller) SetDERPMapFn(fn func() *DERPMap) {
	p.derpMap = fn
}

// WaitForUpdate blocks until the state version exceeds sinceVersion or ctx is cancelled.
// Returns the current NetworkState when unblocked.
func (p *Poller) WaitForUpdate(ctx context.Context, sinceVersion int64) NetworkState {
	// Subscribe to state changes.
	ch, cancel := p.store.subscribe()
	defer cancel()

	// Check immediately — maybe there's already a newer version.
	if p.store.UpdatedAt().UnixNano() > sinceVersion {
		return p.snapshot()
	}

	// Wait for update or timeout.
	timer := time.NewTimer(pollMaxWait)
	defer timer.Stop()

	select {
	case <-ch:
	case <-timer.C:
	case <-ctx.Done():
	}
	return p.snapshot()
}

// snapshot builds the current NetworkState.
func (p *Poller) snapshot() NetworkState {
	nodes := p.store.ListNodes()
	acl := p.store.GetACL()
	ns := NetworkState{
		Version:   p.store.UpdatedAt().UnixNano(),
		UpdatedAt: p.store.UpdatedAt().UTC().Format(time.RFC3339),
		Nodes:     nodes,
		ACL:       acl,
	}
	if p.derpMap != nil {
		ns.DERPMap = p.derpMap()
	}
	return ns
}

# Comprehensive Go Codebase Security Audit

**Project**: karadul — WireGuard-compatible mesh VPN
**Date**: 2026-04-03
**Codebase**: ~35,000 lines of Go across 90+ files
**Dependencies**: golang.org/x/crypto, golang.org/x/sys, gorilla/websocket
**Auditor**: Automated deep review (4 parallel sub-agents + manual cross-cutting analysis)

---

## Executive Summary

Karadul is a well-structured mesh VPN implementation following the Noise IK handshake pattern (WireGuard-compatible crypto). The codebase demonstrates strong fundamentals: proper use of `crypto/rand`, consistent `io.LimitReader` usage, good HTTP server timeout configuration, and a clean package architecture with proper `internal/` boundaries.

However, the audit uncovered **critical authentication design flaws** (HMAC using public key as secret, timing oracle on auth key lookup), a **replay window bitmap bug** that undermines anti-replay protection, **path traversal** in the key store, several **high-severity race conditions** in the mesh peer and logger subsystems, and a **relay double-close race**. The cryptographic implementation is sound algorithmically but lacks key material zeroing, which is standard practice for VPN software. The coordinator API has an information disclosure vulnerability exposing the admin secret.

Overall, this is a competent early-stage VPN implementation that needs targeted fixes before production deployment, particularly around the authentication scheme and concurrency safety.

---

## CRITICAL Issues (Fix Immediately)

### CRITICAL-1: HMAC Authentication Uses Public Key as Secret — Any Node Can Impersonate Any Other

**Category**: Security / Authentication Bypass
**Files**: `internal/coordinator/auth.go:59-67`, `internal/coordinator/auth.go:97-109`, `internal/node/engine.go:468-473`
**Impact**: Complete authentication bypass — any registered node can forge requests as any other node

**Current Code** (`internal/coordinator/auth.go:59-67`):
```go
// Both client and server use the node's public key as the HMAC key so
// the coordinator can verify using only the registered public key.
func SignRequest(pubKey [32]byte, method, path string, body []byte) string {
    msg := append([]byte(method+"\n"+path+"\n"), body...)
    mac := crypto.HMAC(pubKey[:], msg)
    return base64.StdEncoding.EncodeToString(mac[:])
}
```

**Problem**: The HMAC key is the node's **public** key. Public keys are returned by multiple API endpoints (`/api/v1/peers`, `/api/v1/topology`, `/api/v1/admin/nodes`). Any party that knows a node's public key can forge valid authenticated requests impersonating that node. This means:
- Any registered node can update another node's endpoint (redirect traffic)
- Any registered node can send pings as another node (keep stale nodes alive)
- Any registered node can poll as another node (obtain network state)

**Recommendation**: Use asymmetric signatures (Ed25519 `Sign`/`Verify`) or derive a shared secret via ECDH between the node's private key and the server's public key. The server should never use a public value as a symmetric authentication key.

---

### CRITICAL-2: Admin Config Endpoint Exposes AdminSecret in GET Response

**Category**: Security / Information Disclosure
**File**: `internal/coordinator/api.go:940-943`
**Impact**: Admin authentication token leaked to any authenticated client

**Current Code**:
```go
case http.MethodGet:
    writeJSON(w, a.cfg)
```

**Problem**: `GET /api/v1/admin/config` serializes the entire `ServerConfig` struct including `AdminSecret`. Any client with admin auth (or any client when no secret is configured) can read the admin token. Combined with CRITICAL-1, this is especially dangerous because the public-key HMAC auth on `/api/v1/peers` could allow any node to retrieve all public keys, then the admin secret could be obtainable through chained attacks.

**Recommendation**: Create a sanitized response type that omits `AdminSecret`, or tag it `json:"-"` and handle it separately.

---

### CRITICAL-3: No Key Material Zeroing After Handshake Completion

**Category**: Security / Cryptography
**Files**: `internal/crypto/noise.go` (entire file), `internal/crypto/x25519.go:24-55`
**Impact**: Private keys and shared secrets persist in memory indefinitely

**Problem**: After `TransportKeys()` is called, the entire `HandshakeState` — including `localStatic.Private`, `localEphemeral.Private`, all DH shared secrets (`es`, `ss`, `ee`, `se`), `ck`, and `k` — remains in memory until GC collects it non-deterministically. The `Session` struct also retains `sendKey`/`recvKey` without zeroing on rotation (the old key values may remain in heap memory).

WireGuard explicitly zeroes handshake state after deriving transport keys. Memory disclosure attacks (cold boot, core dumps, `/proc/mem`, swap files) can recover these secrets.

**Recommendation**: Add a `Destroy()` method to `HandshakeState` that zeroes all sensitive fields. Call it immediately after `TransportKeys()`. Also zero DH intermediates (`es`, `ss`, `ee`, `se`) immediately after `MixKey` in each handshake message function.

```go
func (hs *HandshakeState) Destroy() {
    for i := range hs.localStatic.Private { hs.localStatic.Private[i] = 0 }
    for i := range hs.localEphemeral.Private { hs.localEphemeral.Private[i] = 0 }
    for i := range hs.ck { hs.ck[i] = 0 }
    for i := range hs.k { hs.k[i] = 0 }
}
```

---

### CRITICAL-4: Data Races on Peer Struct Fields

**Category**: Concurrency / Race Condition
**Files**: `internal/mesh/peer.go:48-58`, `internal/node/engine.go` (multiple locations)
**Impact**: Undefined behavior, potential corruption, race detector failures

**Problem**: `Peer.Hostname`, `Peer.VirtualIP`, `Peer.Routes`, and `Peer.State` are protected by `Peer.mu` but are freely read without holding the lock throughout the engine:
- `engine.go:579` — `ps.peer.Hostname` read without lock
- `engine.go:1032-1034` — `peer.Hostname`, `peer.GetEndpoint()` read without lock
- `engine.go:1124-1135` — `p.Hostname`, `p.NodeID`, `p.VirtualIP` read without lock
- `engine.go:1189-1195` — `p.Hostname`, `p.VirtualIP.String()` read without lock
- `engine.go:1309` — `mesh.PeerSummary(p)` reads multiple fields without lock

Any concurrent `AddOrUpdate` call from the poll loop that modifies these fields will race.

**Recommendation**: Either (a) make all mutable fields unexported with getter methods that acquire the lock, or (b) document and enforce that `Hostname`/`VirtualIP`/`PublicKey`/`NodeID` are immutable after construction and only use accessor methods for `State`, `Routes`, and `Endpoint`.

---

### CRITICAL-5: Logger SetLevel/SetFormat Race on Package-Level Default

**Category**: Concurrency / Race Condition
**File**: `internal/log/logger.go:102, 157-158`
**Impact**: Data race on concurrent logging with level changes

**Current Code**:
```go
func SetLevel(level Level)    { Default.level = level }
func SetFormat(format Format) { Default.format = format }

func (l *Logger) log(level Level, msg string, args []interface{}) {
    if level < l.level {  // read without lock
        return
    }
```

**Problem**: `SetLevel`/`SetFormat` write to `Default.level`/`Default.format` without holding `Default.mu`. The `log()` method reads `l.level` without holding `mu` (the lock is only acquired later at line 117). This is a data race under concurrent use.

**Recommendation**: Use `atomic.Int32` for level and format, or hold `mu` when reading/writing these fields.

---

### CRITICAL-6: Replay Window Bitmap Indexing Bug

**Category**: Security / Cryptography
**File**: `internal/crypto/replay.go:34-36, 58-60`
**Impact**: Both false-positive replay rejections and false-negative replay acceptance

**Current Code**:
```go
// Check (line 34-36):
idx := (counter % WindowSize) / 64
bit := counter % 64
return w.bitmap[idx]&(1<<bit) == 0

// Advance (line 58-60):
idx := (counter % WindowSize) / 64
bit := counter % 64
w.bitmap[idx] |= 1 << bit
```

**Problem**: The bitmap uses `counter % WindowSize` for indexing, but after `slideBy()` shifts the bitmap contents, the mapping between counter values and bitmap positions becomes inconsistent. `slideBy` performs a linear shift of the bitmap array, but `Check`/`Advance` use modular arithmetic on the absolute counter value, which doesn't account for the shift.

Example: floor=0, counter=64 is in bitmap[1]. After `slideBy(1)`, floor=1, but counter=64's bit was shifted from bitmap[1] to bitmap[0]. However, `Check(64)` still computes `idx = (64 % 2048) / 64 = 1`, looking at the wrong word. This means the replay window can both fail to detect replays (attacker can resend packets) and falsely reject legitimate packets.

**Recommendation**: Use offset-based indexing relative to floor:
```go
offset := counter - w.floor
idx := offset / 64
bit := offset % 64
```
And change `slideBy` to zero only vacated slots without shifting.

---

### CRITICAL-7: Path Traversal in KeyStore Load/Delete

**Category**: Security / Path Traversal
**File**: `internal/auth/keys.go:82-83, 149-151`
**Impact**: Arbitrary file read/delete on the filesystem

**Current Code**:
```go
func (ks *KeyStore) Load(id string) (*PreAuthKey, error) {
    path := filepath.Join(ks.dir, id+".json")

func (ks *KeyStore) Delete(id string) error {
    return os.Remove(filepath.Join(ks.dir, id+".json"))
```

**Problem**: The `id` parameter is not sanitized. An attacker controlling the `id` value can use path traversal (e.g., `../../etc/shadow`) to read or delete arbitrary files. While `filepath.Join` normalizes `..` components, it does not prevent them from escaping the intended directory.

**Recommendation**: Validate that `id` contains only safe characters (alphanumeric, hyphens) and verify the resolved path stays under `ks.dir`:
```go
if !regexp.MustCompile(`^[a-zA-Z0-9-]+$`).MatchString(id) {
    return nil, fmt.Errorf("invalid key ID")
}
```

---

### CRITICAL-8: Timing Side-Channel in Auth Key Secret Comparison

**Category**: Security / Timing Attack
**File**: `internal/auth/keys.go:116`
**Impact**: Auth key secret can be recovered byte-by-byte via timing oracle

**Current Code**:
```go
if k.Secret == secret {
    return k, nil
}
```

**Problem**: `FindBySecret` uses `==` for secret comparison, which is not constant-time. An attacker can probe secret values using timing measurements to determine which prefix matches, recovering the full key.

**Recommendation**: Use `subtle.ConstantTimeCompare([]byte(k.Secret), []byte(secret)) == 1`.

---

## HIGH Issues (Fix This Sprint)

### HIGH-1: Relay Server Double-Close Race on Client Eviction

**Category**: Concurrency / Panic Risk
**File**: `internal/relay/server.go:198-215`
**Impact**: Runtime panic from double-close of channel

**Problem**: When a client reconnects with the same public key, `addClient` closes `old.send`. The old client's deferred `removeClient` call will later close the *new* client's `send` channel (since `removeClient` looks up by `pubKey`, not by instance). This can cause:
1. The new client's send goroutine to exit prematurely
2. A potential double-close panic if timing aligns

**Recommendation**: Compare pointer identity in `removeClient` (`s.clients[pubKey] == sc`) or use a `sync.Once` for channel closing:
```go
func (s *Server) removeClient(sc *serverClient) {
    s.mu.Lock()
    if current, ok := s.clients[sc.pubKey]; ok && current == sc {
        delete(s.clients, sc.pubKey)
        close(sc.send)
    }
    s.mu.Unlock()
}
```

---

### HIGH-2: buildSession Leaks Old Session IDs in byID Map

**Category**: Resource Leak / Memory
**File**: `internal/node/engine.go:938-953`
**Impact**: Unbounded map growth, stale session IDs

**Problem**: When `buildSession` replaces an existing session for the same `remotePub`, the old entry in `e.byID[oldLocalID]` is never deleted. Over time this causes unbounded growth. Compare with `RekeyPeer` (line 1266) which properly cleans up.

**Recommendation**:
```go
e.mu.Lock()
if old, ok := e.sessions[remotePub]; ok {
    delete(e.byID, old.localID)
}
e.sessions[remotePub] = ps
e.byID[localID] = ps
e.mu.Unlock()
```

---

### HIGH-3: HMAC Function Is Misnamed — Not RFC 2104 HMAC

**Category**: Security / Cryptography
**File**: `internal/crypto/blake2s.go:31-45`
**Impact**: Misleading API, potential interoperability issues

**Problem**: The `HMAC()` function uses BLAKE2s keyed-hash mode, not RFC 2104 HMAC construction. While BLAKE2s keyed mode is a secure MAC, the fallback path for keys > 32 bytes silently hashes the key down, which differs from HMAC's key handling. The name is dangerously misleading.

**Recommendation**: Rename to `KeyedMAC` or `BLAKE2sMAC` and document that this is BLAKE2s keyed mode, not HMAC.

---

### HIGH-4: WebSocket Missing SetReadLimit — Denial of Service

**Category**: Security / DoS
**File**: `internal/coordinator/websocket.go:435-459`
**Impact**: Unbounded memory allocation from malicious WebSocket clients

**Problem**: No `SetReadLimit` is called on the WebSocket connection. A malicious client can send arbitrarily large messages causing OOM.

**Recommendation**: Add `c.conn.SetReadLimit(4096)` since the server only reads and discards messages.

---

### HIGH-5: Relay Server and Client Use Plain TCP — No TLS

**Category**: Security / Transport
**Files**: `internal/relay/server.go:247-275`, `internal/relay/client.go:104-105`
**Impact**: Metadata exposure, potential traffic manipulation

**Problem**: All DERP relay traffic is sent over plain TCP. While the inner packets are encrypted (Noise IK), the relay connection exposes metadata: which public keys are communicating, packet sizes, timing. The client performs no server authentication.

**Recommendation**: Add TLS support with certificate verification, or document that the relay must be deployed behind a TLS-terminating reverse proxy.

---

### HIGH-6: math/rand Used for Security-Adjacent Timing in Hole Punch

**Category**: Security / Weak Randomness
**File**: `internal/nat/holepunch.go:6, 81`
**Impact**: Predictable jitter timing

**Current Code**:
```go
import "math/rand"
// ...
jitter := time.Duration(rand.Int63n(int64(hpJitter*2))) - hpJitter
```

**Problem**: `math/rand` is not cryptographically secure. While the jitter is only for timing, predictable jitter patterns could theoretically help an attacker who is observing NAT traversal attempts to interfere with hole punching.

**Recommendation**: Use `crypto/rand` for the jitter, or at minimum document why `math/rand` is acceptable here.

---

### HIGH-7: Race Condition in Admin Config Update

**Category**: Concurrency / Race Condition
**File**: `internal/coordinator/api.go:966-975`
**Impact**: Corrupted config persistence

**Current Code**:
```go
a.cfgMu.Lock()
*a.cfg = cfg
a.cfgMu.Unlock()
// Persist config to disk.
if a.cfg.DataDir != "" {          // reads a.cfg without lock
    configPath := a.cfg.DataDir + "/config.json"
```

**Problem**: After releasing `cfgMu`, the code reads `a.cfg.DataDir` and passes `a.cfg` to `SaveServerConfig` without holding the lock. A concurrent PUT could modify `a.cfg` between unlock and these reads.

**Recommendation**: Capture `DataDir` and a config snapshot inside the locked section.

---

### HIGH-8: initiateHandshake TOCTOU Race on Pending Check

**Category**: Concurrency / Race Condition
**File**: `internal/node/engine.go:766-798`
**Impact**: Duplicate handshakes, wasted resources

**Problem**: The check for existing pending handshakes uses `RLock`, then releases it before acquiring `Lock` to add the new pending entry. Two goroutines could both pass the check simultaneously.

**Recommendation**: Combine the check and insert under a single `Lock`.

---

### HIGH-9: DNS Resolver Potentially Acts as Open Resolver

**Category**: Security / Network
**File**: `internal/dns/resolver.go` (bind address `100.64.0.53:53`)
**Impact**: DNS amplification attacks if reachable from outside the mesh

**Problem**: The DNS resolver forwards all non-magic-domain queries to the upstream without source validation. If the resolver is bound to an address reachable from outside the mesh network, it becomes an open DNS resolver usable for amplification attacks.

**Recommendation**: Validate that DNS queries originate from the mesh subnet (`100.64.0.0/10`). Add source IP filtering.

---

## MEDIUM Issues (Fix Soon)

### MEDIUM-1: context.Context Stored in Engine Struct

**File**: `internal/node/engine.go:127-128`

Storing `context.Context` in a struct is explicitly warned against in Go docs. If `connectPeer` is called before `Start()` sets `e.ctx`, this panics on nil context. Pass context as a parameter through the `ConnectFunc` signature.

### MEDIUM-2: WebSocket WritePump Batches Multiple JSON Messages Into Single Frame

**File**: `internal/coordinator/websocket.go:480-489`

Multiple independent JSON objects are concatenated with newlines into a single WebSocket text frame. Clients parsing this as a single JSON message will fail.

### MEDIUM-3: STUN MAPPED-ADDRESS Aliases Underlying Buffer

**File**: `internal/nat/stun.go:158-159`

`parseMappedAddress` creates `net.IP` as a direct slice alias into the response buffer. If the buffer is reused, the IP address will be silently corrupted.

### MEDIUM-4: Node Re-Registration Skips Auth Key Validation Path

**File**: `internal/coordinator/api.go:292-312`

When a node re-registers (public key already exists), the re-registration path runs after auth key validation, but the update itself does not verify that the *same* auth key was used. A different (valid) auth key could be used to update an existing node's properties.

### MEDIUM-5: Relay Server maxClients Check Is Racy (TOCTOU)

**File**: `internal/relay/server.go:120-126`

The client count check uses `RLock`, reads, releases, then proceeds. Between check and `addClient`, multiple goroutines could exceed `maxClients`.

### MEDIUM-6: Excessive Use of interface{} / map[string]interface{}

**Files**: `internal/coordinator/websocket.go` (15+ instances), `internal/log/logger.go`, `internal/node/engine.go:1300`

Widespread use of `map[string]interface{}` for JSON serialization instead of typed structs. This bypasses compile-time type checking and makes the API contract implicit.

### MEDIUM-7: Engine.shutdown Does Not Wait for Goroutines

**File**: `internal/node/engine.go:257-280`

`shutdown()` closes channels and resources but does not use `sync.WaitGroup` to wait for the 8+ goroutines launched in `Start()` to actually exit. This can cause races during shutdown.

### MEDIUM-8: Auth Key Lookup Not Constant-Time

**File**: `internal/coordinator/storage.go:289-299`

`GetAuthKey` uses string equality (`k.Key == secret`) to find auth keys, which is not constant-time. This enables timing-based secret enumeration.

**Recommendation**: Use `subtle.ConstantTimeCompare`.

### MEDIUM-9: Private Key File Permissions Not Validated on Load

**File**: `internal/crypto/x25519.go:136-150`

`LoadKeyPair` reads the private key file without checking permissions. If the file is world-readable (0644), the private key is exposed. WireGuard warns if key files have lax permissions.

### MEDIUM-10: Missing WebSocket Message Size Limit on Gorilla Upgrader

**File**: `internal/coordinator/websocket.go:45-49`

The global `upgrader` has `CheckOrigin: func(r *http.Request) bool { return true }`. While this is overridden per-hub, the global default allows any origin if used directly.

---

## LOW Issues (Tech Debt)

### LOW-1: Duplicate Topology/Peer Building Logic

The topology and peer-building logic in `websocket.go` (`buildTopologyFromNodes`, `buildPeersFromNodes`) is nearly identical to the logic in `api.go` (`handleTopology`, `handlePeers`). This should be extracted into shared functions.

### LOW-2: Engine Is a God Object

`internal/node/engine.go` at 1413 lines handles registration, STUN, polling, handshakes, packet forwarding, DERP relay, DNS, ACL, local API, metrics, exit nodes, and rekey. This should be decomposed into smaller subsystems.

### LOW-3: Missing Package-Level Documentation

Several packages lack `// Package foo ...` godoc comments: `mesh`, `nat`, `tunnel`, `firewall`, `relay`, `config`.

### LOW-4: Inconsistent Error Wrapping

Some errors use `fmt.Errorf("...: %w", err)` while others use `fmt.Errorf("...: %v", err)` or just `return err` without context.

### LOW-5: Hardcoded DNS Upstream Default

`internal/node/engine.go:220` defaults to `1.1.1.1:53`. This should be documented and potentially configurable per-platform.

### LOW-6: sync.Pool with interface{} Return

`internal/node/engine.go:152` uses `func() interface{}` for the pool's `New` function. With Go 1.18+, this could use generics, though this is a minor style issue.

### LOW-7: Missing Struct Field Ordering for Alignment

Several structs (e.g., `Engine`, `peerSession`) mix pointer, atomic, and scalar fields without considering memory alignment padding.

---

## Build & Configuration Issues

### BUILD-1: go.mod Requires Go 1.25 but CI Tests on Go 1.24

**Files**: `go.mod` (line 3), `.github/workflows/ci.yml` (line 16)

`go.mod` specifies `go 1.25.0` but CI matrix includes `go-version: ['1.24', '1.25']`. Go 1.24 cannot build this module.

### BUILD-2: Dockerfile Uses `alpine:latest` — Non-Reproducible

**File**: `Dockerfile:28`

Using `alpine:latest` for the runtime image means builds are not reproducible. Pin to a specific version.

### BUILD-3: Missing golangci-lint Configuration File

No `.golangci.yml` found. The CI runs `golangci-lint` with default settings, which may miss project-specific rules.

---

## Positive Observations

1. **Consistent io.LimitReader usage**: All `io.ReadAll` calls use `io.LimitReader` — no unbounded reads
2. **Proper HTTP timeouts**: Both the coordinator server and the node's HTTP client have explicit timeouts
3. **Good use of crypto/rand**: All security-critical randomness uses `crypto/rand` (except the one `math/rand` in holepunch)
4. **Atomic counters for metrics**: Proper use of `atomic.Uint64` for packet/byte counters
5. **Constant-time comparisons**: Admin auth and WebSocket auth use `subtle.ConstantTimeCompare`
6. **No InsecureSkipVerify**: TLS verification is never disabled
7. **No SQL injection risk**: No SQL database is used; state is stored in JSON files
8. **No command injection**: All `exec.Command` calls use argument arrays, not shell interpolation
9. **Proper DERP relay protocol**: The relay correctly handles presence, routing, and keepalives
10. **Good test coverage structure**: Fuzz tests, benchmark tests, coverage tests, and integration tests exist

---

## Priority Matrix

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 8     | Auth bypass, key zeroing, data races, info disclosure, replay window bug, path traversal, timing oracle |
| HIGH     | 9     | Race conditions, missing TLS, DoS vectors, memory leaks |
| MEDIUM   | 10    | Context misuse, protocol bugs, timing attacks, permissions |
| LOW      | 7     | Code quality, style, tech debt |

---

## Recommended Action Plan

### Phase 1: Critical Security (Immediate)
1. **Replace HMAC-public-key auth** with proper asymmetric signatures (CRITICAL-1)
2. **Sanitize admin config response** to exclude AdminSecret (CRITICAL-2)
3. **Add key material zeroing** to HandshakeState and Session (CRITICAL-3)
4. **Fix peer field data races** with proper accessor methods (CRITICAL-4)
5. **Fix logger level race** with atomic operations (CRITICAL-5)
6. **Fix replay window bitmap indexing** — use offset-based indexing relative to floor (CRITICAL-6)
7. **Sanitize KeyStore IDs** to prevent path traversal (CRITICAL-7)
8. **Use constant-time comparison** for auth key secret lookup (CRITICAL-8)

### Phase 2: High-Priority Fixes (This Sprint)
1. Fix relay server double-close race (HIGH-1)
2. Fix byID map leak in buildSession (HIGH-2)
3. Add WebSocket read limits (HIGH-4)
4. Add TLS to relay server/client (HIGH-5)
5. Fix admin config race condition (HIGH-7)
6. Fix initiateHandshake TOCTOU (HIGH-8)
7. Add DNS source filtering (HIGH-9)

### Phase 3: Medium-Priority Improvements
1. Fix context storage in Engine struct
2. Fix WebSocket message batching
3. Add auth key constant-time lookup
4. Validate private key file permissions
5. Fix STUN buffer aliasing

### Phase 4: Tech Debt
1. Extract shared topology logic
2. Decompose Engine god object
3. Add package documentation
4. Standardize error wrapping

---

## Scores

| Metric | Score | Notes |
|--------|-------|-------|
| **Code Health** | 7/10 | Well-structured, good package boundaries, but god object in engine.go |
| **Security** | 3/10 | Critical auth flaw, replay window bug, path traversal, timing oracle, missing key zeroing, no TLS on relay |
| **Concurrency Safety** | 5/10 | Multiple data races, missing WaitGroup, TOCTOU bugs |
| **Maintainability** | 7/10 | Clean architecture, good test infrastructure, but large files |
| **Test Coverage** | 7/10 | Good test structure with fuzz/bench tests, coverage tests exist |
| **Overall Risk** | HIGH | The HMAC auth bypass alone warrants immediate remediation |

---

*Report generated from exhaustive review of all 90+ Go source files across 14 packages.*

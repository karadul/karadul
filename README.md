# Karadul

> **Karadul** — Self-hosted, zero-dependency mesh VPN system written in Go.

[![CI](https://github.com/karadul/karadul/actions/workflows/ci.yml/badge.svg)](https://github.com/karadul/karadul/actions)
[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/karadul/karadul)](https://goreportcard.com/report/github.com/karadul/karadul)
[![Release](https://img.shields.io/github/v/release/karadul/karadul?include_prereleases)](https://github.com/karadul/karadul/releases)

> 🧪 **Beta Available:** [v0.1.0-beta.1](https://github.com/karadul/karadul/releases/tag/v0.1.0-beta.1) now with Windows support! [Test it out →](https://github.com/karadul/karadul/releases)

---

## What is Karadul?

Karadul is a WireGuard-compatible, self-hosted mesh VPN system that enables secure peer-to-peer connectivity across NAT boundaries. It combines a coordination server, encrypted tunnels, NAT traversal, and relay infrastructure into a **single Go binary with zero external dependencies**.

Think of it as: **Tailscale + Headscale in one binary, built from scratch.**

### Core Philosophy

| Principle | Description |
|-----------|-------------|
| **Zero External Dependencies** | Only Go stdlib + extended stdlib. All other components hand-written. |
| **Single Binary** | One binary serves all roles: node, coordination server, DERP relay. |
| **Self-Hosted First** | No SaaS dependency. You own the coordination server, DERP relays, all keys. |
| **WireGuard-Compatible Protocol** | Uses Noise IK handshake, X25519, ChaCha20-Poly1305, BLAKE2s. |

---

## Quick Start

### Installation

#### macOS (Homebrew)
```bash
brew tap karadul/karadul
brew install karadul
```

#### Linux (Binary)
```bash
# Download latest release
curl -LO https://github.com/karadul/karadul/releases/latest/download/karadul-linux-amd64
chmod +x karadul-linux-amd64
sudo mv karadul-linux-amd64 /usr/local/bin/karadul
```

#### Windows
```powershell
# PowerShell - Download and install
Invoke-WebRequest -Uri "https://github.com/karadul/karadul/releases/latest/download/karadul-windows-amd64.exe" -OutFile "karadul.exe"
# Move to PATH (e.g., C:\Windows\System32 or create C:\Tools and add to PATH)
```

#### Docker
```bash
docker run -d --name karadul \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -p 8080:8080 \
  -p 3478:3478/udp \
  ghcr.io/karadul/karadul:latest \
  server --addr=:8080
```

#### Build from Source
```bash
go install github.com/karadul/karadul/cmd/karadul@latest
# or
git clone https://github.com/karadul/karadul.git
cd karadul
go build -o karadul ./cmd/karadul
```

### Usage

```bash
# Start as coordination server
karadul server --addr=:8080

# Create an auth key
karadul auth create-key

# On another node, join the mesh
karadul up --server=https://your-server:8080 --auth-key=<key>

# Check status
karadul status
```

---

## Karadul vs. Alternatives

| Feature | **Karadul** | **Tailscale** | **Headscale** | **NetMaker** | **ZeroTier** |
|---------|-------------|---------------|---------------|--------------|--------------|
| **Architecture** | Single binary, all-in-one | Client + SaaS control plane | Self-hosted control plane (separate) | Self-hosted server + agents | Centralized controller |
| **Self-Hosted** | ✅ Native | ❌ SaaS only | ✅ Yes | ✅ Yes | ⚠️ Partial (root servers) |
| **Zero Dependencies** | ✅ Go stdlib only | ❌ Various deps | ❌ PostgreSQL, etc. | ❌ MongoDB, CoreDNS | ❌ Custom protocol |
| **Single Binary** | ✅ Yes | ❌ Client + daemon | ❌ Server + DB | ❌ Server + DB + UI | ❌ Client + controller |
| **Built-in DERP Relay** | ✅ Yes | ✅ Yes | ⚠️ Requires separate setup | ❌ Separate | ✅ Yes |
| **WireGuard Protocol** | ✅ Compatible | ✅ Yes | ✅ Yes | ⚠️ Modified | ❌ Custom |
| **MagicDNS** | ✅ Built-in | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **ACL Support** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **NAT Traversal** | ✅ STUN + Hole Punching | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Exit Nodes** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Platforms** | Linux, macOS, Windows, BSD | All platforms | All platforms | Linux, macOS, Windows, BSD | All platforms |
| **Mobile Support** | 🚧 Planned | ✅ iOS/Android | ✅ Via Tailscale client | ✅ iOS/Android | ✅ All platforms |
| **Open Source** | ✅ MIT | ❌ Client only | ✅ BSD-3 | ✅ Apache 2.0 | ❌ BUSL/SSPL |
| **Complexity** | Low (one binary) | Low (managed) | Medium (setup required) | Medium (setup required) | Low (managed) |

### When to Choose Karadul

**Choose Karadul if you want:**
- A **truly single-binary** solution with no database dependencies
- **Zero external dependencies** (no PostgreSQL, MongoDB, etc.)
- Full **self-hosting** without relying on any SaaS
- To **understand and audit** the entire codebase (pure Go, hand-written components)
- A lightweight alternative that **just works** with minimal configuration

**Choose Tailscale if you want:**
- A **managed SaaS** with zero operational overhead
- Proprietary features like Mullvad VPN integration
- Large-scale enterprise support

**Choose Headscale if you want:**
- Self-hosted Tailscale-compatible control plane
- Already familiar with Tailscale ecosystem
- Don't mind running PostgreSQL + separate services

**Choose NetMaker if you want:**
- Self-hosted WireGuard management with UI
- Enterprise-grade network management features
- Don't mind MongoDB/CoreDNS dependencies

**Choose ZeroTier if you want:**
- A managed solution with custom protocol (not WireGuard)
- Easy setup via web interface
- Don't need self-hosting capability

---

## Web UI

Karadul includes a built-in web interface for monitoring and managing your mesh network.

### Features
- **Dashboard** — System metrics, traffic stats, and network overview
- **Topology** — Interactive mesh network graph (React Flow)
- **Nodes** — Node list, search, details panel, and management
- **Peers** — Peer connections, filtering, and status
- **Settings** — Auth keys, ACL rules, and general configuration
- **Real-time** — WebSocket updates for live data
- **Dark/Light mode** — Theme toggle

### Quick Start

```bash
# Start the server with web UI enabled
karadul server --addr=:8080 --web-addr=:8081

# Or build from source with web UI
make build-with-web
```

The web UI runs on port 8081 by default and proxies API requests to the coordinator on port 8080.

### Development

```bash
cd web
npm install
npm run dev       # Development server at http://localhost:5173
npm run test      # Run tests (416 tests, 96%+ coverage)
npm run build     # Production build
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        karadul binary                       │
│                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐   │
│  │  CLI    │  │  Node   │  │ Coord   │  │  DERP Relay  │   │
│  │ Engine  │  │ Engine  │  │ Server  │  │   Server     │   │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬───────┘   │
│       └─────────────┴─────────────┴─────────────┘            │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              Web UI (React + TypeScript)              │    │
│  │  Dashboard │ Topology │ Nodes │ Peers │ Settings     │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                             │                                │
│                    Core Libraries                            │
│  ┌─────────┐ ┌─────────┐ ┌──────┐ ┌─────────┐ ┌─────────┐  │
│  │ crypto  │ │ tunnel  │ │ nat  │ │  mesh   │ │   dns   │  │
│  │ (noise) │ │  (tun)  │ │(stun)│ │(peers)  │ │(magic)  │  │
│  └─────────┘ └─────────┘ └──────┘ └─────────┘ └─────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Commands

```bash
# Node commands
karadul up                    # Start as mesh node
karadul down                  # Stop the node
karadul status                # Show node status
karadul peers                 # List connected peers
karadul ping <peer>           # Ping a specific peer

# Server commands
karadul server                # Start coordination server
karadul server --with-relay   # Coordination + DERP relay
karadul relay                 # Start DERP relay only

# Admin commands
karadul keygen                # Generate node keypair
karadul auth-keys create      # Create authentication key
karadul exit-node enable      # Enable as exit node
karadul exit-node use <peer>  # Route traffic through peer

# Windows-specific (beta)
karadul wintun-check          # Check Wintun driver installation
karadul firewall setup        # Add Windows Firewall rules
karadul firewall check        # Check firewall configuration
```

---

## Security

- **Noise Protocol Framework** — Modern, formally-verified cryptographic handshake
- **X25519** — Elliptic Curve Diffie-Hellman key exchange
- **ChaCha20-Poly1305** — Authenticated encryption (AEAD)
- **BLAKE2s** — Fast cryptographic hashing
- **No hardcoded keys** — All keys generated at runtime
- **Self-hosted** — You control all infrastructure and keys

---

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) — Detailed technical specification
- [Architecture Decision Records](contrib/adr/) — Design decisions and rationale
- [Windows Beta Guide](contrib/WINDOWS_BETA_GUIDE.md) — Windows installation and usage
- [Beta Release Checklist](contrib/BETA_RELEASE_CHECKLIST.md) — Post-release tasks
- [Roadmap](ROADMAP.md) — Future plans and milestones

---

## Support

If you find Karadul useful, please consider:

- ⭐ [Star the repository](https://github.com/karadul/karadul)
- 🧪 [Test beta releases](https://github.com/karadul/karadul/releases)
- 🐛 [Report bugs](../../issues)
- 💻 [Contribute code](CONTRIBUTING.md)

See [FUNDING.md](FUNDING.md) for sponsorship options.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <i>"Ağ ören, mesh kuran, dokunduğu her noktayı birbirine bağlayan sistem"</i>
</p>

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of mesh VPN system
- WireGuard-compatible protocol (Noise IK handshake, X25519, ChaCha20-Poly1305)
- Coordination server with REST API
- DERP relay for NAT traversal fallback
- STUN-based NAT traversal with hole punching
- MagicDNS implementation
- ACL-based access control
- Single binary with zero external dependencies
- Support for Linux and macOS
- Exit node functionality
- Comprehensive test suite (>90% coverage for core packages)

### Core Packages
- `internal/crypto` - Noise protocol implementation, X25519, ChaCha20-Poly1305
- `internal/tunnel` - TUN device management (Linux, macOS)
- `internal/nat` - STUN client and hole punching
- `internal/coordinator` - Coordination server and state management
- `internal/mesh` - Peer management and topology
- `internal/relay` - DERP relay server
- `internal/auth` - Authentication keys and validation
- `internal/dns` - MagicDNS resolver

## [0.1.0] - TBD

### Added
- Initial release
- Basic mesh networking
- Coordination server
- NAT traversal

[Unreleased]: https://github.com/ersinkoc/karadul/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ersinkoc/karadul/releases/tag/v0.1.0

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2026-03-26

### Added
- **Windows Support (Beta)** - Wintun integration for Windows TUN devices
  - `internal/tunnel/tun_windows.go` - Windows TUN implementation using Wintun driver
  - `internal/tunnel/wintun_dll_windows.go` - Wintun DLL loading and management
  - `internal/tunnel/wintun_dll_other.go` - Non-Windows stubs
  - `karadul wintun-check` command to verify Wintun driver installation
- **Cross-Platform Firewall Management**
  - `internal/firewall/firewall_windows.go` - Windows Firewall netsh integration
  - `internal/firewall/firewall_linux.go` - Linux firewall stubs
  - `internal/firewall/firewall_darwin.go` - macOS firewall stubs
  - `internal/firewall/firewall_bsd.go` - BSD firewall stubs
  - `karadul firewall` command with `setup`, `remove`, `check`, `allow-port` subcommands
- **GitHub Actions Workflows**
  - `release.yml` - Automated binary releases for 10+ platforms
  - `container.yml` - Docker image builds and GHCR publishing
- **Docker Support**
  - `Dockerfile` - Multi-stage build for minimal runtime image
  - `docker-compose.yml` - Example Docker Compose configuration
- **Homebrew Formula** - macOS/Linux Homebrew tap support
  - `contrib/homebrew/karadul.rb.template` - Formula template
  - `contrib/homebrew/update-formula.sh` - Formula update script
- **Release Infrastructure**
  - `scripts/release.sh` - Automated release preparation
  - `contrib/RELEASE_CHECKLIST.md` - Release documentation

### Changed
- Updated CI workflow to test all supported platforms (Linux, macOS, Windows, FreeBSD, OpenBSD)
- Updated README with new installation methods (Homebrew, Docker, Windows binary)
- Expanded comparison table to include Windows support

### Platform Support
- ✅ Linux (amd64, arm64, armv7) - Fully Supported
- ✅ macOS (amd64, arm64) - Fully Supported
- ⚠️ Windows (amd64, arm64, x86) - Beta (Wintun integration, needs testing)
- ⚠️ FreeBSD (amd64) - Best Effort (Build OK, TUN stub)
- ⚠️ OpenBSD (amd64) - Best Effort (Build OK, TUN stub)

### Known Issues
- Windows: TUN driver requires manual Wintun DLL installation
- Windows: Some features may be unstable (beta quality)
- BSD: TUN implementation is stubbed (returns error)

## [0.1.0] - TBD

### Added
- Initial stable release
- Basic mesh networking
- Coordination server
- NAT traversal

[Unreleased]: https://github.com/ersinkoc/karadul/compare/v0.1.0-beta.1...HEAD
[0.1.0-beta.1]: https://github.com/ersinkoc/karadul/releases/tag/v0.1.0-beta.1
[0.1.0]: https://github.com/ersinkoc/karadul/releases/tag/v0.1.0

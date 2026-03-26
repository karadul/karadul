# Release Checklist

This document describes the release process for Karadul.

## Current Version

See [VERSION](../VERSION) file.

## Release Types

### Beta/Pre-release
- Version format: `v0.1.0-beta.1`, `v0.1.0-rc.1`
- Marked as pre-release on GitHub
- For testing before stable release

### Stable Release
- Version format: `v0.1.0`, `v0.2.0`
- Full production ready
- Follows [Semantic Versioning](https://semver.org/)

## Automated Release (Recommended)

### Step 1: Run Release Script

```bash
# Using the release script (sets version automatically)
./scripts/release.sh v0.1.0
```

Or manually:

```bash
# Update VERSION file
echo "v0.1.0" > VERSION

# Update version in main.go
sed -i '' 's/const version = ".*"/const version = "0.1.0"/' cmd/karadul/main.go

# Commit
git add VERSION cmd/karadul/main.go
git commit -m "chore: release v0.1.0"

# Create and push tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin main
git push origin v0.1.0
```

### Step 2: GitHub Actions Takes Over

After pushing the tag, GitHub Actions automatically:

1. **Test Job**
   - Runs on Ubuntu and macOS
   - Tests with Go 1.23 and 1.24
   - Runs race detector tests

2. **Build Job**
   - Builds for 10 platforms:
     - Linux (amd64, arm64, arm)
     - macOS (amd64, arm64)
     - Windows (amd64, arm64, x86)
     - FreeBSD (amd64)
     - OpenBSD (amd64)

3. **Container Job**
   - Builds Docker image for linux/amd64 and linux/arm64
   - Pushes to GitHub Container Registry (ghcr.io)

4. **Release Job**
   - Creates GitHub Release with all binaries
   - Generates checksums
   - Auto-generates release notes

### Step 3: Verify Release

Check the following:

- [ ] GitHub Actions workflow completed successfully
- [ ] All binaries attached to release
- [ ] Checksums file present
- [ ] Docker image available on GHCR
- [ ] Release notes accurate

## Manual Release (Not Recommended)

If you need to release manually:

```bash
# Build all binaries
GOOS=linux GOARCH=amd64 go build -o karadul-linux-amd64 ./cmd/karadul
GOOS=linux GOARCH=arm64 go build -o karadul-linux-arm64 ./cmd/karadul
GOOS=darwin GOARCH=amd64 go build -o karadul-darwin-amd64 ./cmd/karadul
GOOS=darwin GOARCH=arm64 go build -o karadul-darwin-arm64 ./cmd/karadul
GOOS=windows GOARCH=amd64 go build -o karadul-windows-amd64.exe ./cmd/karadul

# Generate checksums
sha256sum karadul-* > checksums.txt

# Create release on GitHub
gh release create v0.1.0 \
  --title "Karadul v0.1.0" \
  --notes "Release notes here" \
  karadul-* checksums.txt
```

## Post-Release Tasks

### Update Homebrew Formula

```bash
# Run the update script
./contrib/homebrew/update-formula.sh v0.1.0

# This generates contrib/homebrew/karadul.rb with updated checksums
# Copy to homebrew tap repo:
cp contrib/homebrew/karadul.rb ../homebrew-karadul/Formula/
cd ../homebrew-karadul
git add Formula/karadul.rb
git commit -m "karadul: update to v0.1.0"
git push
```

### Update Documentation

- [ ] Update CHANGELOG.md
- [ ] Update README.md if needed
- [ ] Update installation instructions

### Announce

- [ ] GitHub Discussions
- [ ] Social media (if applicable)
- [ ] Community channels

## Versioning Guidelines

- **Major** (X.0.0): Breaking changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible
- **Pre-release** (v0.1.0-beta.1): Testing versions

## Platform Support Status

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Fully Supported | All features work |
| macOS | ✅ Fully Supported | All features work |
| Windows | ⚠️ Experimental | TUN works, needs testing |
| FreeBSD | ⚠️ Best Effort | Build OK, TUN not implemented |
| OpenBSD | ⚠️ Best Effort | Build OK, TUN not implemented |

## Emergency Hotfix

If a critical bug is found after release:

1. Fix the bug on main branch
2. Create a new patch version:
   ```bash
   ./scripts/release.sh v0.1.1
   ```
3. If the previous release was broken, mark it as deprecated in release notes

## Rollback

To remove a release:

```bash
# Delete tag locally and remotely
git tag -d v0.1.0
git push origin :refs/tags/v0.1.0

# Delete GitHub release (via web UI or gh CLI)
gh release delete v0.1.0
```

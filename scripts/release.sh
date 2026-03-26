#!/bin/bash
# Release script for Karadul
# Usage: ./scripts/release.sh [version]
# Example: ./scripts/release.sh v0.1.0

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$PROJECT_ROOT"

# Get version from argument or VERSION file
if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(cat VERSION 2>/dev/null || echo "")
fi

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.1.0"
    echo ""
    echo "Or set version in VERSION file:"
    echo 'echo "v0.1.0" > VERSION'
    exit 1
fi

# Ensure version starts with 'v'
if [[ ! "$VERSION" =~ ^v ]]; then
    VERSION="v${VERSION}"
fi

echo "🦅 Karadul Release Script"
echo "========================="
echo ""
echo "Version: $VERSION"
echo ""

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Working directory is not clean."
    echo "Please commit or stash your changes before releasing."
    git status --short
    exit 1
fi

echo "✅ Working directory is clean"

# Run tests
echo ""
echo "🧪 Running tests..."
if go test -race ./...; then
    echo "✅ Tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi

# Build for all platforms to ensure everything compiles
echo ""
echo "🔨 Building for all platforms..."
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
    "windows/386"
)

for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    echo -n "  Building for $os/$arch... "
    if GOOS="$os" GOARCH="$arch" go build -o "/dev/null" ./cmd/karadul 2>/dev/null; then
        echo "✓"
    else
        echo "✗"
        exit 1
    fi
done

# Update version in main.go if needed
echo ""
echo "📝 Checking version in main.go..."
CURRENT_VERSION=$(grep "^const version" cmd/karadul/main.go | sed 's/.*= "\(.*\)".*/\1/')
if [ "$CURRENT_VERSION" != "${VERSION#v}" ]; then
    echo "  Updating version in main.go: $CURRENT_VERSION → ${VERSION#v}"
    sed -i.bak "s/const version = \".*\"/const version = \"${VERSION#v}\"/" cmd/karadul/main.go
    rm cmd/karadul/main.go.bak
    git add cmd/karadul/main.go
    git commit -m "chore: bump version to $VERSION"
else
    echo "  Version is already correct: $CURRENT_VERSION"
fi

# Create git tag
echo ""
echo "🏷️  Creating git tag..."
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "  Tag $VERSION already exists"
else
    git tag -a "$VERSION" -m "Release $VERSION"
    echo "  Created tag: $VERSION"
fi

echo ""
echo "📦 Release $VERSION is ready!"
echo ""
echo "To push and trigger the release:"
echo "  git push origin main"
echo "  git push origin $VERSION"
echo ""
echo "Or push everything at once:"
echo "  git push origin main --tags"
echo ""
echo "GitHub Actions will automatically:"
echo "  • Build binaries for all platforms"
echo "  • Create a GitHub Release"
echo "  • Build and push Docker images"
echo ""

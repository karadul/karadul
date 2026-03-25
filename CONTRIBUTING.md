# Contributing to Karadul

Thank you for your interest in contributing to Karadul! This document provides guidelines for contributing to the project.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ersinkoc/karadul.git
cd karadul

# Install dependencies
make dev-setup

# Run tests
make test

# Build the binary
make build
```

## Project Structure

```
.
├── cmd/karadul/          # Main application entry point
├── internal/
│   ├── auth/             # Authentication and authorization
│   ├── config/           # Configuration management
│   ├── coordinator/      # Coordination server
│   ├── crypto/           # Cryptographic operations
│   ├── dns/              # MagicDNS implementation
│   ├── log/              # Structured logging
│   ├── mesh/             # Mesh network management
│   ├── nat/              # NAT traversal (STUN, hole punching)
│   ├── node/             # Node engine
│   ├── protocol/         # Protocol definitions
│   ├── relay/            # DERP relay server
│   └── tunnel/           # TUN device management
├── contrib/              # Additional resources
└── SPECIFICATION.md      # Technical specification
```

## Coding Standards

- **Go Version**: Minimum Go 1.23
- **Code Style**: Follow standard Go conventions (`gofmt`, `go vet`)
- **Testing**: Write tests for new functionality
- **Documentation**: Document exported functions and types
- **Error Handling**: Use descriptive error messages

## Testing

```bash
# Run all tests
make test

# Run tests with race detector
make test-race

# Run tests with coverage
make test-cover

# Generate HTML coverage report
make test-cover-html
```

## Submitting Changes

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** with clear commit messages
3. **Add tests** for any new functionality
4. **Ensure all tests pass**: `make check`
5. **Update documentation** if needed
6. **Submit a Pull Request**

### Commit Message Format

```
<type>: <short summary>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:
```
feat: add support for exit nodes

Implement exit node functionality allowing nodes to route
traffic through a designated peer.

Closes #123
```

## Code Review Process

All submissions require review before being merged. The maintainers will:

- Review the code for quality and correctness
- Ensure tests are adequate
- Verify documentation is updated
- Check for security implications

## Security

If you discover a security vulnerability, please email security@karadul.dev instead of opening a public issue.

## Questions?

- Open an issue for bugs or feature requests
- Join discussions in existing issues
- Check SPECIFICATION.md for technical details

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

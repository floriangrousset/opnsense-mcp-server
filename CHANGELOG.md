# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI/CD pipeline with GitHub Actions (ci.yml, security.yml, release.yml)
- Pre-commit hooks configuration for code quality
- Developer tooling: Makefile, .editorconfig, .dockerignore
- CHANGELOG.md for tracking project changes
- Modernized Docker configuration with multi-stage builds

### Changed
- Docker configuration updated to use new src/ structure
- Docker image now runs as non-root user for security

## [1.0.0] - 2025-10-05

### Added
- Comprehensive security hardening (Phase 1-3)
  - 12 dependency updates fixing 5 CVEs (including CVSS 9.1 RCE)
  - Error message sanitization preventing credential leakage
  - Dangerous endpoint protection blocking 33 high-risk operations
  - SSL/TLS 1.2+ enforcement preventing protocol downgrade attacks
  - Comprehensive port validation preventing firewall misconfigurations
  - Automatic credential rotation detection
  - Password security warnings in user management
  - Extended SECURITY.md documentation (+316 lines)

### Security
- Fixed CVE-2025-43859 (Critical - CVSS 9.1): httpx/h11 RCE vulnerability
- Fixed CVE-2025-53366 (High - CVSS 7.5): MCP SDK DoS vulnerability
- Fixed CVE-2024-3772 (Medium - CVSS 6.5): Pydantic ReDoS
- Fixed CVE-2024-21503 (Medium - CVSS 6.5): Black ReDoS
- Fixed CVE-2025-4574 (Medium - CVSS 5.3): Ruff Rust dependencies

## [0.9.0] - 2025-10-04

### Added
- Complete modular architecture refactoring
- 166 MCP tools across 12 specialized domain modules
- 296 comprehensive tests with 100% pass rate
- CLI tools for setup, testing, and profile management
- Secure local-only credential storage
- Connection pooling and rate limiting

### Changed
- Migrated from monolithic 9,529-line file to modular structure
- Improved error handling and logging
- Enhanced documentation (README, CONTRIBUTING, SECURITY)

---

## How to Update This Changelog

When making changes, add entries under the `[Unreleased]` section in the appropriate category:

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

When creating a release:
1. Change `[Unreleased]` to the version number with date: `[1.1.0] - 2025-10-15`
2. Add a new `[Unreleased]` section at the top
3. Update the version comparison links at the bottom

---

[Unreleased]: https://github.com/floriangrousset/opnsense-mcp-server/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/floriangrousset/opnsense-mcp-server/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/floriangrousset/opnsense-mcp-server/releases/tag/v0.9.0

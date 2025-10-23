# GitHub Actions Workflows Setup

This repository includes comprehensive CI/CD workflows for the Vault Audit Tools Rust project.

## Workflows

### 1. CI Pipeline (`.github/workflows/ci.yml`)
**Triggers:** Push to main, Pull requests, Manual dispatch

**Jobs:**
- **Test Suite** - Runs on Ubuntu, macOS, Windows
  - Executes all unit tests
  - Runs doc tests
  - Cross-platform validation

- **Linting** - Clippy with warnings as errors
  - Ensures code quality
  - Catches common mistakes

- **Formatting** - rustfmt check
  - Enforces consistent code style

- **Build** - Release builds on all platforms
  - Uploads build artifacts
  - 7-day retention

- **Coverage** - Code coverage with cargo-tarpaulin
  - Uploads to Codecov
  - Tracks test coverage over time

### 2. Security Scanning (`.github/workflows/security.yml`)
**Triggers:** Push, Pull requests, Daily at 2 AM UTC, Manual

**Jobs:**
- **Snyk** - Dependency vulnerability scanning
  - Checks for known CVEs
  - Uploads results to GitHub Security

- **Cargo Audit** - RustSec advisory database
  - Checks for security advisories
  - Fails on HIGH severity

- **Cargo Deny** - License and security checks
  - Validates licenses (MIT, Apache-2.0, BSD)
  - Blocks GPL/AGPL licenses
  - Checks for unmaintained dependencies

- **Dependency Review** - PR-only
  - Reviews new dependencies
  - Fails on moderate+ vulnerabilities

### 3. Release Pipeline (`.github/workflows/release.yml`)
**Triggers:** Version tags (v*.*.*), Manual dispatch

**Jobs:**
- **Create Release** - Creates GitHub release
  - Auto-generates release notes
  - Includes installation instructions

- **Build Release Binary** - Multi-platform builds
  - Linux (x86_64 GNU and musl)
  - macOS (Intel and Apple Silicon)
  - Windows (x86_64 MSVC)
  - Generates SHA256 checksums
  - Uploads to GitHub Releases

- **Publish to crates.io** - Optional
  - Publishes to Rust package registry
  - Requires CARGO_REGISTRY_TOKEN secret

### 4. Dependabot (`.github/dependabot.yml`)
**Schedule:** Weekly on Monday at 9 AM

**Updates:**
- Cargo dependencies
- GitHub Actions versions
- Auto-assigns to maintainer
- Labels PRs appropriately

## Required Secrets

To fully utilize all workflows, configure these secrets in GitHub Settings:

1. **CODECOV_TOKEN** (Optional)
   - Get from https://codecov.io
   - Used for code coverage reporting

2. **SNYK_TOKEN** (Optional)
   - Get from https://snyk.io
   - Used for vulnerability scanning

3. **CARGO_REGISTRY_TOKEN** (Optional)
   - Get from https://crates.io/me
   - Required only if publishing to crates.io

## Creating a Release

### Automatic (Recommended)
1. Create and push a version tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. GitHub Actions will automatically:
   - Build binaries for all platforms
   - Create GitHub release with assets
   - Generate checksums
   - Optionally publish to crates.io

### Manual
1. Go to Actions → Release workflow
2. Click "Run workflow"
3. Enter version (e.g., v0.1.0)
4. Click "Run workflow"

## Status Badges

Add these to your README.md:

```markdown
[![CI](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/ci.yml)
[![Security](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml/badge.svg)](https://github.com/trenner1/hashicorp-vault-audit-analysis/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/trenner1/hashicorp-vault-audit-analysis/branch/main/graph/badge.svg)](https://codecov.io/gh/trenner1/hashicorp-vault-audit-analysis)
```

## Local Development

### Run tests
```bash
cd vault-audit-tools
cargo test
```

### Check formatting
```bash
cargo fmt --all -- --check
```

### Run clippy
```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Security audit
```bash
cargo install cargo-audit cargo-deny
cargo audit
cargo deny check
```

### Build release
```bash
cargo build --release
```

## Troubleshooting

### Snyk fails with missing token
- Add SNYK_TOKEN secret or disable Snyk job in security.yml

### Codecov upload fails
- Add CODECOV_TOKEN secret or set `fail_ci_if_error: false`

### cargo-deny fails on license
- Review and update allowed licenses in `vault-audit-tools/deny.toml`

### Release build fails
- Ensure version tag follows semver (vX.Y.Z)
- Check Cargo.toml version matches tag

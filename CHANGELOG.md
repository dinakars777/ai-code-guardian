# Changelog

## [0.11.0] - 2026-03-24

### Fixed
- **CRITICAL**: Fixed OSV API deserialization crash when packages have zero vulnerabilities
- **CRITICAL**: TUI panic hook added - terminal now properly restores on crash
- **CRITICAL**: TUI false positives now affect exit code - marking all issues as false positives no longer exits with code 1
- Reduced eval() false positives - now requires non-alphanumeric character before eval (excludes retrieval, approval, medieval, etc.)
- Reduced HTTP URL noise - now excludes localhost, 127.0.0.1, 0.0.0.0, example.com, and XML schema URIs
- Reduced hardcoded IP false positives - now excludes 127.0.0.1, 0.0.0.0, and 255.255.255.x subnet masks

### Performance
- HTTP client now reused across all dependency vulnerability checks (was creating new client per request)

### Cleanup
- Removed internal OpenClaw setup document
- Removed scan output file from repository
- Updated .gitignore to block scan output files

## [0.10.0] - 2026-03-24

### Added
- Dependency vulnerability checking with OSV.dev API integration
- Support for Python (requirements.txt, pyproject.toml), Node (package.json), and Rust (Cargo.toml)
- LiteLLM supply chain attack case study on landing page

### Fixed
- SQL injection pattern now requires FROM/INTO/SET keywords to reduce false positives on logging

## [0.9.0] - 2026-03-23

### Fixed
- Improved SQL injection detection pattern

## [0.8.0] - 2026-03-22

### Added
- GitHub Pages landing page with animations and interactive demo
- GitHub topics for better discoverability

## Earlier versions
- Initial releases with core scanning functionality, TUI, watch mode, custom rules, git integration

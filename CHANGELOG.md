# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-01

### Added

- Initial release of Sentinel
- Rust core with PyO3 bindings for fast analysis
- 24 analysis rules across 4 categories:
  - Security (8 rules): SQL injection, shell injection, eval/exec, hardcoded secrets, insecure random, path traversal, debug code, unsafe deserialization
  - Correctness (7 rules): unclosed resources, mutable defaults, bare except, except-pass, return-in-init, comparison-to-none, unreachable code
  - Compliance (5 frameworks): HIPAA, SOC 2, GDPR, PCI DSS, SOX
  - Anti-Cheat (4 rules): linter evasion, dynamic imports, string obfuscation, conditional suppression
- Evidence generation with reproduction tests for each finding
- Compliance scoring system
- CLI with Typer and Rich
- Three output formats: Terminal, JSON, HTML
- GitHub Action for PR reviews
- VS Code extension with inline diagnostics
- Pre-commit hook support
- Docker support
- Comprehensive test suite (25 tests)

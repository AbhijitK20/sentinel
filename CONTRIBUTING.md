# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel! This document provides guidelines and information about contributing to this project.

## Development Setup

### Prerequisites

- Python 3.10+
- Rust 1.70+
- [maturin](https://github.com/PyO3/maturin) (for building the Rust+Python package)

### Setup

```bash
# Clone the repository
git clone https://github.com/sentinel/sentinel.git
cd sentinel

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Install maturin
pip install maturin

# Build the Rust core
maturin develop

# Run tests
pytest tests/
cargo test
```

## Project Structure

```
sentinel/
├── src/                    # Rust core
│   ├── lib.rs             # PyO3 module entry
│   ├── ast.rs             # AST parsing utilities
│   ├── report.rs          # Data models
│   ├── evidence.rs        # Evidence generation
│   └── rules/             # Analysis rules
├── sentinel/              # Python package
│   ├── cli.py             # CLI interface
│   ├── __init__.py        # Package exports
│   └── _lib.pyi           # Type stubs
├── tests/                 # Test suite
└── .github/               # CI/CD
```

## Adding a New Rule

1. **Create the rule** in `src/rules/<category>.rs`:

```rust
pub fn check_my_rule(path: &str, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (i, line) in source.lines().enumerate() {
        if /* condition */ {
            let ev = evidence::generate_my_proof(line.trim());
            findings.push(Finding::new(
                format!("my-rule-{}", i),
                "my-rule".to_string(),
                Severity::Warning,  // or Error, Info
                Category::Security, // or Correctness, Compliance, AntiCheat
                path.to_string(),
                i + 1,
                0,
                "Description of the issue".to_string(),
                "How to fix it".to_string(),
                0.85,  // confidence
                Some(ev),
                None,
                None,
            ));
        }
    }
    findings
}
```

2. **Register it** in `src/rules/mod.rs`:

```rust
findings.extend(security::check_my_rule(path, source));
```

3. **Add evidence** in `src/evidence.rs`:

```rust
pub fn generate_my_proof(code_line: &str) -> Evidence {
    Evidence::new(
        "# Reproduction code...".to_string(),
        "Expected behavior".to_string(),
        "Actual behavior".to_string(),
        "behavioral".to_string(),
    )
}
```

4. **Write tests** in `tests/test_core.py`:

```python
def test_my_rule(self):
    code = "vulnerable code here\n"
    report = scan_source(code, "test.py")
    assert "my-rule" in [f.rule for f in report.findings]
```

5. **Update the rules table** in `README.md`.

## Code Style

### Rust

- Follow `rustfmt` defaults
- Use `clippy` warnings as guidance
- Document public functions with `///` comments

### Python

- Follow `black` formatting
- Type hints required for all public functions
- Docstrings for all public functions (Google style)

## Testing

- All new rules must have corresponding tests
- Tests should cover both positive (finding exists) and negative (no false positive) cases
- Run the full test suite before submitting:

```bash
pytest tests/ -v
cargo test
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

### PR Description

Please include:

- **What** the change does
- **Why** the change is needed
- **How** it was tested
- Any breaking changes

## Reporting Bugs

When reporting bugs, please include:

- Sentinel version (`sentinel --version`)
- Python version
- Operating system
- Minimal reproduction case
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

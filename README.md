# 🛡️ AI Code Guardian

Security scanner for AI-generated code. Catches vulnerabilities before you commit.

## The Problem

AI coding tools are great, but they introduce security risks:
- Hardcoded API keys and secrets
- SQL injection vulnerabilities
- Insecure HTTP requests
- Exposed credentials

This tool scans your code and catches these issues instantly.

## What Makes Us Different

- **Interactive TUI mode** - Navigate issues with arrow keys, mark false positives
- **Auto-fix suggestions** - Don't just find issues, get actionable solutions
- **Lightning fast** - Written in Rust, 10x faster than Node.js alternatives
- **Single binary** - No npm, no node_modules, just one executable
- **Beautiful output** - Color-coded, easy to read results
- **100% local** - No data leaves your machine

## Installation

```bash
cargo install ai-code-guardian
```

## Usage

```bash
# Scan current directory
ai-guardian scan

# Scan specific directory
ai-guardian scan ./src

# Interactive TUI mode
ai-guardian scan --interactive

# Scan with JSON output
ai-guardian scan --json
```

## What It Detects

- **Hardcoded Secrets**: API keys, passwords, tokens
- **SQL Injection**: Unsafe query construction
- **Insecure HTTP**: Unencrypted connections
- **Exposed Credentials**: .env files, config files

## Example Output

```
🛡️  AI Code Guardian - Security Scan

Scanning: ./src

❌ HIGH: Hardcoded API Key
   File: src/api.rs:12
   Found: const API_KEY = "sk-1234567890abcdef"
   Risk: Exposed credentials in source code
   Fix: Use process.env.API_KEY or import from .env file

❌ HIGH: SQL Injection Risk
   File: src/db.rs:45
   Found: query = "SELECT * FROM users WHERE id = " + user_id
   Risk: Unsanitized user input in SQL query
   Fix: Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])

✅ Scan complete: 2 issues found
```

## Pre-commit Hook

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
ai-guardian scan
if [ $? -ne 0 ]; then
    echo "Security issues found. Commit blocked."
    exit 1
fi
```

## How It Works

1. Walks through your codebase
2. Scans files for security patterns
3. Reports high-risk issues
4. Suggests fixes

No data leaves your machine. Everything runs locally.

## Roadmap

- [ ] XSS detection
- [ ] Path traversal detection
- [ ] Custom rule engine
- [ ] CI/CD integration
- [ ] VS Code extension

## Contributing

Found a false positive? Have a pattern to add? PRs welcome!

## License

MIT

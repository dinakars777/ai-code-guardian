# Setting Up AI Code Guardian for OpenClaw

## Quick Setup

1. **Copy the workflow file** to OpenClaw repo:
   ```bash
   mkdir -p .github/workflows
   cp examples/github-action-pr-only.yml .github/workflows/security.yml
   ```

2. **Commit and push**:
   ```bash
   git add .github/workflows/security.yml
   git commit -m "Add AI Code Guardian security scanning"
   git push
   ```

3. **Done!** Now every PR will be automatically scanned.

## What Happens

- When someone opens a PR, GitHub Actions will:
  1. Install AI Code Guardian
  2. Scan only the changed files (fast!)
  3. Report any security issues
  4. Block the PR if critical issues are found

## Reducing Noise

Since OpenClaw has 348 HTTP URL warnings in comments, you might want to:

1. **Create `.guardianignore`** to exclude third-party code:
   ```
   # Ignore third-party libraries
   Box2D/
   ThirdParty/
   ClawLauncher/
   
   # Ignore generated files
   *.vcxproj
   *.vcxproj.filters
   ```

2. **Scan only high severity issues** (modify the workflow):
   ```yaml
   - name: Scan changed files
     run: ai-guardian scan --git | grep "HIGH"
   ```

## Testing Locally

Before pushing, test it locally:
```bash
# Install
cargo install ai-code-guardian

# Scan the whole repo
ai-guardian scan .

# Scan only your changes
ai-guardian scan --git
```

## Benefits for OpenClaw

- Catches hardcoded secrets before they're committed
- Prevents SQL injection vulnerabilities
- Blocks insecure API calls
- Zero maintenance (runs automatically)
- Fast (only scans changed files)

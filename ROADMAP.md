# AI Code Guardian Roadmap

Created: 2026-05-23

## Current Baseline

The project is now on a verified green baseline:

- `cargo fmt -- --check`
- `cargo test`
- `cargo clippy -- -D warnings`
- `cargo run -- scan . --verbose`
- GitHub Actions CI runs the same checks on pull requests and `main`

Recent stabilization work fixed scanner build drift, an unsupported Rust regex look-ahead, project-wide formatting drift, self-scan false positives, and missing CI coverage.

## Roadmap Principles

- Prefer low-noise findings over broader but noisy pattern coverage.
- Keep checks fast enough for pre-commit and pull-request workflows.
- Treat dependency scanning, source scanning, and reporting as separate surfaces with explicit tests.
- Make CI/CD integrations first-class outputs, not examples that users must adapt by hand.

## Phase 1: Correctness Coverage

Goal: make the scanner safer to change without reintroducing false positives, crashes, or parser regressions.

1. Add parser tests for dependency files.
   - Evidence: `src/deps.rs` parses `requirements.txt`, `package.json`, `Cargo.toml`, and `pyproject.toml`, but the current test suite only covers scanner pattern behavior.
   - Work: add fixture-based tests for supported dependency file formats, version operators, dev/build/optional dependency sections, and unsupported file errors.
   - Success: parser behavior is covered without hitting the network.

2. Add rule fixture tests for built-in detections.
   - Evidence: built-in patterns in `src/patterns.rs` have high user impact and several already need post-match filtering in `src/scanner.rs`.
   - Work: introduce true-positive and false-positive fixtures per rule, including API keys, SQL injection variants, HTTP URLs, IP addresses, eval usage, JWT secrets, and database URLs.
   - Success: each built-in rule has at least one true-positive and one false-positive regression test where applicable.

3. Give built-in rules stable IDs.
   - Evidence: scanner filters currently branch on human-facing titles such as `"Hardcoded Secret"` and `"Dangerous eval() Usage"`.
   - Work: add an internal rule ID field and route post-match filters by ID, while preserving current titles in user output.
   - Success: changing display copy cannot break filtering behavior.

## Phase 2: Dependency Scanning Hardening

Goal: make `check-deps` accurate and usable for real projects.

1. Use OSV batch queries.
   - Evidence: `check_dependencies` currently sends one `/v1/query` request per dependency with a delay. OSV documents `POST /v1/querybatch` for multiple packages in one request.
   - Work: batch dependency queries, map responses back to packages, and preserve clear per-package output.
   - Success: large manifests complete with fewer network round trips and equivalent findings.
   - Reference: https://google.github.io/osv.dev/post-v1-querybatch/

2. Add lockfile support.
   - Evidence: `src/deps.rs` reads manifest files but not lockfiles, so resolved versions can be missed or approximated.
   - Work: support `Cargo.lock`, `package-lock.json`, and common Python lockfiles where feasible.
   - Success: dependency checks prefer resolved versions when a lockfile is present.

3. Make network behavior explicit.
   - Evidence: OSV calls have no visible timeout, retry policy, or offline behavior beyond returning an error.
   - Work: add request timeouts, bounded retries for transient failures, and a clear offline/error mode in JSON and text output.
   - Success: CI users can distinguish "no vulnerabilities" from "dependency service unavailable."

## Phase 3: Reporting And Integrations

Goal: make findings easy to consume in developer workflows.

1. Add SARIF output.
   - Evidence: the CLI has text and JSON output, but GitHub code scanning and many security dashboards use SARIF.
   - Work: add `ai-guardian scan --sarif` and map severity, rule metadata, file, line, and fix suggestions.
   - Success: GitHub can ingest scanner results as code-scanning alerts.

2. Build an official GitHub Action.
   - Evidence: `examples/` contains copy-paste workflow snippets that install from crates.io.
   - Work: publish a first-party action wrapper with inputs for path, changed-files-only mode, output format, and fail severity.
   - Success: users can add AI Code Guardian with a single `uses:` step.

3. Add severity threshold controls.
   - Evidence: `scan` exits nonzero only for high-risk issues, while dependency checks exit nonzero for any vulnerability.
   - Work: add `--fail-on high|medium|low|none` consistently across source and dependency scans.
   - Success: CI policy is explicit and predictable.

## Phase 4: Detection Coverage

Goal: expand coverage without sacrificing precision.

1. Add XSS detection.
   - Scope: obvious unsanitized DOM writes and template interpolation patterns in JavaScript/TypeScript and common frontend files.
   - Test posture: fixture-first, with framework-safe examples to avoid noisy alerts.

2. Add path traversal detection.
   - Scope: file reads/writes that concatenate user-controlled path segments without normalization or allowlisting.
   - Test posture: language-specific examples for Node, Python, Go, and Rust.

3. Improve custom rule ergonomics.
   - Scope: schema validation, sample rules, and better diagnostics for invalid custom rule files.
   - Test posture: invalid JSON, invalid regex, invalid severity, and successful custom matches.

## Phase 5: Release And Project Operations

Goal: make releases and maintenance repeatable.

1. Add release automation.
   - Work: check version consistency, run the full CI suite, build release artifacts, and publish crates.io releases through a guarded workflow.
   - Success: release steps are documented and mostly automated.

2. Add dependency maintenance.
   - Work: configure automated dependency update PRs and add a vulnerability audit step suitable for Rust dependencies.
   - Success: stale or vulnerable dependencies surface as PRs or CI failures.

3. Keep docs aligned with behavior.
   - Work: add CLI golden-output checks or doc examples that are exercised in CI.
   - Success: README examples do not drift from actual command behavior.

## Suggested Next PRs

1. Add dependency parser fixture tests for `src/deps.rs`.
2. Add built-in rule true-positive and false-positive fixture tests.
3. Replace title-based scanner filtering with stable rule IDs.
4. Implement `--fail-on` consistently for source and dependency scans.
5. Prototype OSV `querybatch` support behind existing `check-deps` output.

# Contributing to VulnHunters

Thank you for improving VulnHunters. Keep changes focused, reviewable, and evidence-driven.

## Before opening a pull request

1. Create a branch from the current default branch.
2. Add or update meaningful regression tests for behavioral changes.
3. Run `python -m pytest -q`, `ruff check src tests`, and `uv build`.
4. Update the README or relevant documentation when user-facing behavior, configuration, or report schema changes.
5. Describe the security impact, assumptions, test evidence, and any remaining limitations in the pull request.

## Design expectations

- Preserve the boundary between analyzer leads, human-confirmed findings, and verified exploits.
- Treat contract source, provider responses, and tool output as untrusted input.
- Keep provider credentials out of logs, reports, fixtures, and commits.
- Prefer offline, deterministic verification. Any networked behavior must be explicit and documented.
- Maintain source provenance: a report must identify the files, hashes, scope decisions, and tool evidence behind a conclusion.

## Reporting bugs

Use a public issue for reproducible, non-sensitive defects. Follow [SECURITY.md](SECURITY.md) for security-sensitive reports.

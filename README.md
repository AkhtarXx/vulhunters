# VulnHunters

> **Status: under active development.** VulnHunters is a blockchain vulnerability-hunting toolkit for Solidity contracts and repositories. It creates reviewable audit evidence; it does not certify that a protocol is secure.

VulnHunters combines explicit scope planning, subscription-backed AI review, Slither static analysis, Foundry test evidence, and a human review gate. It writes machine-readable JSON and SARIF alongside a Markdown report so that security teams can inspect the evidence, triage leads, and enforce CI policy.

## What it does

- Selects Solidity files using an explainable scope plan, with `scope.txt`, automatic production-code discovery, and a full-repository override.
- Records source hashes, import relationships, tool versions, and every included or excluded file.
- Uses the official Codex or Claude Code subscription login. Hermes OAuth transports are also supported when Hermes is installed. No vendor API key is required for these modes.
- Runs Slither over the source snapshot and retains detector, severity, confidence, compilation, and source-location evidence.
- Runs Foundry tests offline with FFI and filesystem permissions disabled, then maps declared invariants to actual test results.
- Produces red-team hypotheses and blue-team challenges with `--research`. Optional candidate PoCs are executed against the audited snapshot and receive one bounded correction attempt when Forge returns a diagnostic.
- Keeps AI leads, static-analysis signals, candidate PoCs, human review decisions, and verified exploits distinct in the report.

## Requirements

- Python 3.10 or newer
- An installed provider CLI for AI review: [Codex CLI](https://developers.openai.com/codex/auth) or [Claude Code](https://code.claude.com/docs/en/authentication)
- Optional: [Slither](https://github.com/crytic/slither) for static analysis
- Optional: [Foundry](https://getfoundry.sh/) and a matching `solc` binary for test and PoC execution

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,security]"
.\.venv\Scripts\vulnhunters.exe doctor
```

On macOS and Linux, use `.venv/bin/python` and `.venv/bin/vulnhunters`. The CLI discovers `slither`, `forge`, and `solc` on `PATH`, from the active virtual environment, or from local `.tools` folders. Use `SLITHER_PATH`, `FORGE_PATH`, and `SOLC_PATH` to override discovery.

## Authenticate with a subscription

```powershell
codex login
claude --setting-sources "" auth login
vulnhunters doctor
```

The Claude adapter isolates user settings and removes API-key and gateway environment overrides before it runs. This keeps the audit on the official subscription login rather than silently falling back to API billing.

Hermes direct OAuth is available when Hermes Agent is installed and authenticated:

```powershell
vulnhunters audit path\to\project --provider hermes-codex --model MODEL_ID
vulnhunters audit path\to\project --provider hermes-claude --model MODEL_ID
```

Set `HERMES_SOURCE` and `HERMES_PYTHON` only when Hermes is installed outside its normal location. Account eligibility, plan limits, and any extra-usage charges remain governed by the provider.

## Run an audit

```powershell
# Inspect the planned scope before a review.
vulnhunters scope path\to\project --mode auto

# Subscription-backed audit with static analysis and project tests.
vulnhunters audit path\to\project --provider claude --forge-tests --output audit.json

# Audit every discoverable Solidity source, including tests and vendored code.
vulnhunters audit path\to\project --provider codex --scope full --max-files 1000 --max-total-bytes 20000000

# Offline heuristic review when an AI provider is unavailable.
vulnhunters audit path\to\project --provider static --no-slither
```

`audit` creates `audit.json`, `audit.md`, and `audit.sarif`. `completed` means the configured checks completed for the declared scope. It never means that the protocol is secure or that a finding is proven.

## Scope controls

| Mode | Behavior |
| --- | --- |
| `default` | Uses `scope.txt` when present; otherwise discovers first-party production Solidity. |
| `auto` | Ignores `scope.txt` and re-discovers production Solidity. |
| `explicit` | Requires `scope.txt`; useful for audit engagements with an agreed scope. |
| `full` | Includes all discoverable Solidity source, including tests, scripts, mocks, and vendored libraries. |

Repository discovery prefers `src/` and `contracts/`, excludes generated output and virtual environments, records every decision, and rejects symlink escapes. `--max-files` and `--max-total-bytes` expand review budgets within hard safety caps.

## Protocol model and invariant evidence

Add `audit-manifest.json` to state the protocol assets, actors, trust boundaries, entrypoints, and intended invariants. This gives the audit concrete assumptions rather than asking the model to invent business logic.

```json
{
  "schema_version": 1,
  "protocol": "Vault",
  "chain": "ethereum",
  "entrypoints": ["src/Vault.sol"],
  "assets": ["ETH deposits"],
  "actors": ["depositor", "admin"],
  "trust_boundaries": ["Depositors are untrusted callers"],
  "invariants": [
    {
      "id": "SOLVENCY",
      "statement": "Vault assets cover depositor liabilities",
      "forge_test": "test/Vault.t.sol:VaultTest::invariant_Solvency()"
    }
  ]
}
```

Use `--forge-tests` to run project tests offline. A fully completed run requires a declared protocol model, successful AI and Slither checks, successful Foundry tests, and successful mapped invariant tests. Missing, disabled, or unavailable evidence is reported as `partial`.

## Research and candidate PoCs

```powershell
vulnhunters audit path\to\project --provider claude --research --research-poc
```

Research mode creates separate attacker hypotheses and defender challenges for selected entrypoints and related sources. Each hypothesis has an exact source citation and remains unverified. A candidate PoC is copied into an isolated temporary Foundry project, can import only audited source paths, runs offline, has FFI and filesystem access disabled, and never broadcasts a transaction. If the first candidate fails with a Forge diagnostic, VulnHunters permits one complete correction attempt. Both attempts remain in the report for review.

You can replay a self-contained proof against the immutable audit snapshot:

```powershell
vulnhunters verify path\to\project audit.json path\to\Proof.t.sol
```

A passing PoC proves only that its assertions passed in that local run. Confirm exploitability, impact, and the relevant value flow before treating it as a verified vulnerability.

## Review and CI gate

```powershell
vulnhunters review audit.json decisions.json
vulnhunters gate audit.json --fail-on high --require-reviewed
```

Human decisions use `confirmed`, `false_positive`, or `needs_more_evidence`. Confirmed decisions require impact, preconditions, likelihood, and severity rationale. The gate fails for incomplete reports, incomplete required review, and confirmed findings at or above the chosen severity.

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
uv build
```

The CI workflow runs the same quality checks and package build on supported Python versions. The [audit roadmap](docs/AUDIT_STANDARD_PLAN.md) shows implemented controls and planned work. The [researcher workflow](docs/RESEARCHER_METHOD.md) maps research mode to public audit and verification practices.

## Security and responsible disclosure

Do not publish sensitive vulnerabilities in a public issue. Follow the reporting process in [SECURITY.md](SECURITY.md). This repository is an evolving research tool and should be used alongside qualified human review.

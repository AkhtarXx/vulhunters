# Industry-standard audit roadmap

VulnHunters is an automated triage tool, not a replacement for an independent security audit or a certification. A `completed` run means the configured automated checks executed over the declared source scope. It does not mean the protocol is secure.

## Reference baseline

- [OWASP Smart Contract Security Verification Standard](https://scs.owasp.org/SCSVS/) organizes review by architecture, governance and economic logic, authorization, cross-contract communication, cryptography, oracle dependencies, denial of service, bridges, and component-specific risks.
- [EEA EthTrust Security Levels v3](https://entethalliance.org/specs/ethtrust-sl/v3/) gives a separate specification for evaluating Ethereum smart contracts; this project does not claim EthTrust conformance.
- [Solidity security considerations](https://docs.soliditylang.org/en/latest/security-considerations.html) stress compiler warnings, checks-effects-interactions, explicit assumptions, and peer review.
- [Slither JSON output](https://github.com/crytic/slither/wiki/JSON-output) defines detector impact, confidence, and source mappings. Its [usage guide](https://github.com/crytic/slither/blob/master/docs/src/Usage.md) covers framework compilation and detector selection.
- [Foundry invariant testing](https://getfoundry.sh/forge/invariant-testing) exercises properties over randomized sequences of calls, which is necessary for stateful protocol behavior that source-only checks miss.

## Delivery gates

| Gate | Required evidence | Current state |
| --- | --- | --- |
| Scope and provenance | Explainable auto/file/full/explicit scope decisions, source hashes, chain, provider, timestamps | Implemented; dynamic Hardhat config needs manual review |
| Build coverage | Each in-scope Solidity file compiled; zero-contract analyzer output cannot pass | Implemented for Slither runs |
| Static evidence | Detector rule, confidence, source file and line, source excerpt, unmapped/truncated counts | Implemented; findings require human triage |
| AI review | Bounded input, isolated subscription transport, exact in-scope citations, failure state | Direct import graph, related-file context, and optional red/blue research passes implemented; transitive and protocol-wide reasoning remain limited |
| Protocol model | Roles, privileged paths, dependencies, assets, trust boundaries, explicit invariants | Manifest for assets, actors, trust boundaries, entrypoints and invariants implemented; privileged-path extraction remains planned |
| Dynamic verification | Project tests, fuzz and invariant campaigns, supplied proof replay, reproducible configuration | Offline Foundry project runner and supplied proof replay implemented; external framework support remains planned |
| Findings adjudication | Severity rationale, likelihood, exploit preconditions, false-positive disposition, fix validation | Human decision workflow implemented; remediation retest remains planned |
| Delivery | Versioned report schema, SARIF/CI output, build manifest, reviewer sign-off | Schema v2, SARIF, CI gate, tool versions and source/config hashes implemented; deployment build attestation remains planned |

## Next engineering increments

1. Extend the direct import graph to a protocol model with privileged paths and transitive interactions. Build a control-by-control coverage map; do not silently drop context. See [researcher method](RESEARCHER_METHOD.md).
2. Extend test runners to Hardhat and other frameworks, with explicit sandboxing and network policy. Preserve the tested properties and run counts; passing campaigns do not prove safety.
3. Add remediation and retest linkage to reviewer decisions, including before/after source hashes and regression tests. Keep analyzer signals distinct from confirmed vulnerabilities.
4. For deployed audits, compare verified source, compiler settings and bytecode before claiming the deployed contract matches the review scope. Add schema migrations when future reports change.

The first gate is deliberately strict: a scanner that silently analyzes zero contracts or loses source locations can mislead a reviewer more than a tool that explicitly reports incomplete coverage.

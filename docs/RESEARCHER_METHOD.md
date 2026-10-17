# Researcher workflow translated into VulnHunters

This is a workflow synthesis from primary security-research publications, not a claim that an AI run is equivalent to an independent human audit.

## What the researchers actually do

| Practice | Published basis | VulnHunters behavior |
| --- | --- | --- |
| Freeze scope, commit, architecture and assumptions before review | [OpenZeppelin audit process](https://blog.openzeppelin.com/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits), [Spearbit scoping guide](https://docs.spearbit.com/spearbook/anatomy-of-a-spearbit-review/scoping-and-information-gathering) | Explainable scope, source hashes, import graph and explicit protocol manifest |
| Build a protocol mental model, then reason as an attacker | [Trail of Bits auditor workflow](https://blog.trailofbits.com/2025/07/23/inside-ethcc8-becoming-a-smart-contract-auditor/), [Spearbit system specifications](https://docs.spearbit.com/spearbook/anatomy-of-a-spearbit-review/scoping-and-information-gathering) | Optional `--research` pass produces actor, precondition, attack sequence, impact, violated property and exact source citation |
| Challenge leads before escalating them into findings | [Spearbit review period](https://docs.spearbit.com/spearbook/anatomy-of-a-spearbit-review/security-review-period) | Separate blue-team pass records counter-evidence, missing evidence and a defensive control; hypotheses remain outside the findings list |
| Test stateful properties and inspect counterexamples | [Trail of Bits invariant work](https://blog.trailofbits.com/2024/04/30/curvance-invariants-unleashed/), [Certora invariant caveats](https://docs.certora.com/en/latest/docs/cvl/invariants.html) | Manifest-linked Foundry invariants record actual runs/calls; optional AI-generated PoC is executed offline against the source snapshot, but a passing test is still unreviewed |
| Reproduce a bug safely and quantify impact | [Immunefi PoC guidance](https://immunefi.com/blog/security-guides/how-to-poc-your-bug-leads/), [Immunefi reporting guide](https://immunefi.com/blog/security-guides/how-to-submit-bug-reports-that-get-paid/) | PoC tests run locally; report separates observed test result from exploit verification and requires human severity/impact review |
| Fix, retest and document the disposition | [Spearbit fix period](https://docs.spearbit.com/spearbook/anatomy-of-a-spearbit-review/fix-period), [OpenZeppelin audit process](https://blog.openzeppelin.com/what-is-a-smart-contract-audit-lessons-from-openzeppelins-1000-audits) | Reviewer decisions and CI gate exist; remediation retest linkage is still planned |
| Use a structured control catalogue rather than a single bug checklist | [OWASP SCSVS](https://scs.owasp.org/SCSVS/), [Trail of Bits secure development workflow](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/workflow.md) | Static analysis and explicit assumptions feed the review; control-by-control coverage mapping is still planned |

## Research mode

`vulnhunters audit PROJECT --provider claude --research` selects up to three source files, prioritizing manifest entrypoints and files with import relationships. For each selected file it runs an attacker-hypothesis pass and a separate defender-challenge pass. Each hypothesis must cite a supplied source file and real line, and all outputs are marked unverified. Source-context omissions and skipped files make the research check partial. Increase coverage with `--research-max-files 10`, subject to per-file and related-context budgets.

`--research-poc` asks the model for one candidate Foundry test from a hypothesis the defender did not reject. The test runs only in a temporary offline project with FFI disabled; its source and result are saved for review. A passing generated assertion cannot establish that an exploit or economic impact is real. No test is sent to a live chain. `--research` does not change the status of findings already produced by Slither or the per-file AI pass.

The automated workflow cannot substitute for protocol-owner clarification, independent auditor judgment, review of economic assumptions, or verification that deployed bytecode matches the audited source. [OWASP states it does not certify SCSVS compliance](https://scs.owasp.org/SCSVS/04-Assessment_and_Certification/).

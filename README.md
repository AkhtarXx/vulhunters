# VulHunters v2.0

### AI-Powered Smart Contract Exploit Discovery System

**Built with Google Gemini 3** | [Demo](#demo) | [Architecture](#architecture)

---

## The Problem

DeFi protocols lost **$3.8 Billion** to hacks in 2023-2024. Traditional security tools find bugs but can't prove they're exploitable.

**Current tools fail because:**
- Static analyzers produce 90%+ false positives
- Manual auditing is slow and expensive ($50K-$500K per audit)
- No tool validates if a bug can actually steal funds

---

## Our Solution

**VulHunters** is an autonomous AI agent powered by **Gemini 3** that:

1. **Finds vulnerabilities** in smart contracts using AI reasoning
2. **Writes working exploits** automatically
3. **Proves exploitability** by extracting real profit on forked blockchains

> **Key Innovation:** We don't just find bugs - we prove them by stealing money (on test networks).

---

## How It Works

### Simple Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  SMART       │     │   ANALYZE    │     │   GENERATE   │     │    PROVE     │
│  CONTRACT    │────▶│   + GRAPH    │────▶│   EXPLOIT    │────▶│   PROFIT     │
│  INPUT       │     │   + SLITHER  │     │   CODE       │     │   ON FORK    │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

### Detailed Per-Contract Analysis Flow

```
                         ┌─────────────────────────────────────┐
                         │     📁 Protocol Directory           │
                         │        (scope.txt)                  │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │  PHASE 1: Protocol Analysis         │
                         │  ─────────────────────────────────  │
                         │  • Parse scope.txt                  │
                         │  • Build dependency graph           │
                         │  • Identify trust boundaries        │
                         │  • Map fund flows                   │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │  PHASE 2: Fork Blockchain           │
                         │  ─────────────────────────────────  │
                         │  • Start Anvil fork                 │
                         │  • Clone mainnet state              │
                         │  • Ready for exploit testing        │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │  PHASE 3: Load Pattern Database     │
                         │  ─────────────────────────────────  │
                         │  • 670+ historical DeFi exploits    │
                         │  • Used for PATTERN MATCHING        │
                         │  • Suggests similar attack vectors  │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
              ┌─────────────────────────────────────────────────────────────┐
              │                                                             │
              │              🔄 FOR EACH CONTRACT IN SCOPE                  │
              │                                                             │
              │  ┌───────────────────────────────────────────────────────┐  │
              │  │  STEP 1: Build Contract Graph                        │  │
              │  │  ───────────────────────────────────────────────────  │  │
              │  │                                                       │  │
              │  │    Contract.sol                                       │  │
              │  │        │                                              │  │
              │  │        ├── imports: [Token.sol, Oracle.sol]          │  │
              │  │        ├── calls: Token.transfer(), Oracle.price()   │  │
              │  │        ├── called_by: [Router.deposit()]             │  │
              │  │        └── internal_calls: withdraw() → _update()    │  │
              │  │                                                       │  │
              │  │    This shows ALL RELATED FILES for context          │  │
              │  └───────────────────────────────────────────────────────┘  │
              │                           │                                 │
              │                           ▼                                 │
              │  ┌───────────────────────────────────────────────────────┐  │
              │  │  STEP 2: Run Slither (Static Analysis)               │  │
              │  │  ───────────────────────────────────────────────────  │  │
              │  │                                                       │  │
              │  │    • Run slither on contract                         │  │
              │  │    • Filter noise (keep High/Medium only)            │  │
              │  │    • Extract: reentrancy, access control, etc.       │  │
              │  │                                                       │  │
              │  └───────────────────────────────────────────────────────┘  │
              │                           │                                 │
              │                           ▼                                 │
              │  ┌───────────────────────────────────────────────────────┐  │
              │  │  STEP 3: Gemini 3 Analysis                           │  │
              │  │  ───────────────────────────────────────────────────  │  │
              │  │                                                       │  │
              │  │    Gemini 3 receives:                                 │  │
              │  │    ┌─────────────────────────────────────────────┐   │  │
              │  │    │ • Full contract source code                 │   │  │
              │  │    │ • Function call graph                       │   │  │
              │  │    │ • Cross-contract calls (related files)      │   │  │
              │  │    │ • Slither findings                          │   │  │
              │  │    │ • Pattern matches from 670+ exploits        │   │  │
              │  │    └─────────────────────────────────────────────┘   │  │
              │  │                                                       │  │
              │  │    Gemini 3 can use bash to explore related files:   │  │
              │  │    $ grep -n 'function transfer' ../Token.sol        │  │
              │  │                                                       │  │
              │  └───────────────────────────────────────────────────────┘  │
              │                           │                                 │
              │                           ▼                                 │
              │  ┌───────────────────────────────────────────────────────┐  │
              │  │  STEP 4: Generate & Test Exploit                     │  │
              │  │  ───────────────────────────────────────────────────  │  │
              │  │                                                       │  │
              │  │    If vulnerability found:                           │  │
              │  │    1. Write Exploit.sol (Solidity)                   │  │
              │  │    2. Compile with Forge                             │  │
              │  │    3. Run on forked blockchain                       │  │
              │  │    4. Measure profit extracted                       │  │
              │  │                                                       │  │
              │  └───────────────────────────────────────────────────────┘  │
              │                                                             │
              └─────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │  PHASE 5: Validate All Exploits     │
                         │  ─────────────────────────────────  │
                         │  • Run each exploit on fork         │
                         │  • Check profit ≥ 0.1 ETH           │
                         │  • Calculate USD value              │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │  PHASE 6: Generate Report           │
                         │  ─────────────────────────────────  │
                         │  • JSON report with all findings    │
                         │  • Markdown report with details     │
                         │  • Profit summary                   │
                         └─────────────────────────────────────┘
```

---

## Gemini 3 Integration

VulHunters uses **Gemini 3** as the core AI engine:

| Gemini 3 Feature | How We Use It |
|------------------|---------------|
| **Gemini 3 Pro** | Main reasoning engine - analyzes contracts, finds vulnerabilities |
| **Function Calling** | Executes bash commands, writes Solidity exploit code |
| **Context Caching** | Caches contract code - 80% token cost savings |
| **Long Context** | Analyzes entire protocols (100K+ tokens) |

### Code Example

```python
# ExploitAgent receives full context for each contract
context = {
    "source_code": contract_code,
    "call_graph": {
        "withdraw": ["_updateBalance", "_transfer"],
        "deposit": ["_mint", "_updateBalance"]
    },
    "cross_contract_calls": [
        {"to": "Token", "function": "transfer", "line": 45},
        {"to": "Oracle", "function": "getPrice", "line": 78}
    ],
    "slither_findings": [
        {"type": "reentrancy", "severity": "High", "line": 52}
    ]
}

# Gemini 3 analyzes and generates exploit
result = await exploit_agent.analyze(context)
```

---

## Key Features

### 1. Smart Contract Graph Building

For each contract, we build a complete relationship map:

```
Vault.sol Analysis:
├── Imports: Token.sol, Oracle.sol, Math.sol
├── External Calls:
│   ├── Line 45: Token.transfer(user, amount)
│   ├── Line 78: Oracle.getPrice(asset)
│   └── Line 92: Token.balanceOf(address(this))
├── Called By:
│   └── Router.deposit() → Vault.mint()
└── Internal Call Graph:
    ├── deposit() → _mint() → _updateShares()
    └── withdraw() → _burn() → _transfer()
```

This helps Gemini 3 understand **how contracts interact** and find vulnerabilities at trust boundaries.

### 2. Pattern Matching (670+ Historical Exploits)

We maintain a database of **670+ real DeFi hacks** for pattern matching:

```
Contract has: Flash loan + Price oracle
Pattern Match: Similar to Euler Finance hack ($197M)
Suggested Attack: Flash loan price manipulation
```

### 3. Profit-Based Validation

We don't just report bugs - we **prove they work**:

```
Traditional Tool:              VulHunters:
─────────────────              ─────────────────
"Possible reentrancy           "Reentrancy CONFIRMED
in withdraw()"                  - Exploit: Exploit.sol
                                - Profit: 150 ETH ($450,000)
                                - Tested on forked mainnet"
```

---

## Demo

### Quick Start

```bash
# Install
git clone https://github.com/yourusername/vulhunters
cd vulhunters
pip install -e .

# Configure
echo "GEMINI_API_KEY=your_key" >> .env

# Run audit
vulhunters audit ./protocol/ --chain ethereum
```

### Example Output

```
$ vulhunters audit ./defi-protocol/

[*] PHASE 1: Protocol Analysis
    ├── Found 5 contracts in scope
    ├── Built dependency graph
    └── Identified 3 trust boundaries

[*] PHASE 2: Forking Ethereum mainnet...
    └── Anvil fork ready at localhost:8545

[*] PHASE 3: Loading pattern database...
    └── 670 historical exploits loaded

[*] PHASE 4: Analyzing contracts...

    📊 Vault.sol
       ├── Building call graph...
       ├── Running Slither...
       ├── Gemini 3 analyzing...
       └── Found: 2 vulnerabilities

    📊 Token.sol
       ├── Building call graph...
       ├── Running Slither...
       ├── Gemini 3 analyzing...
       └── Found: 1 vulnerability

[*] PHASE 5: Validating exploits...
    ├── Exploit #1: SUCCESS - 50 ETH ($150,000)
    └── Exploit #2: SUCCESS - 25 ETH ($75,000)

[*] PHASE 6: Generating reports...
    └── report.json, report.md saved

════════════════════════════════════════
SUMMARY
────────────────────────────────────────
Vulnerabilities:     3
Working Exploits:    2
Total Profit:        75 ETH ($225,000)
════════════════════════════════════════
```

---

## Project Structure

```
vulhunters/
├── src/vulhunters/
│   ├── agents/
│   │   ├── exploit_agent_v2.py     # Gemini 3 powered analysis
│   │   ├── protocol_analyzer.py    # Dependency graph builder
│   │   ├── contract_analyzer.py    # Per-contract analysis + Slither
│   │   └── pattern_matcher.py      # 670+ exploit pattern matching
│   ├── gemini/
│   │   └── client.py               # Gemini 3 API client
│   ├── mcp_servers/
│   │   └── anvil_server.py         # Blockchain forking tools
│   ├── harness/
│   │   └── exploit_validator.py    # Profit validation
│   └── unified_cli.py              # CLI entry point
├── DeFiHackLabs/                   # 670+ historical exploits
└── tests/                          # Test suite
```

---

## Impact

| Metric | Traditional Audit | VulHunters |
|--------|-------------------|------------|
| **Cost** | $50K - $500K | ~$100 (API) |
| **Time** | 2-4 weeks | Minutes |
| **False Positives** | 90%+ | ~0% (profit validated) |
| **Exploit Proof** | Manual | Automatic |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| **AI Engine** | Google Gemini 3 Pro |
| **Blockchain** | Foundry (Anvil, Forge, Cast) |
| **Static Analysis** | Slither |
| **Language** | Python 3.11+, Solidity |

---

## License

MIT License

---

<p align="center">
  <b>VulHunters v2.0</b> - Finding DeFi vulnerabilities before hackers do.
</p>

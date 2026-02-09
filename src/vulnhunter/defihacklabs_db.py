"""
DefiHackLabs Database

Index and search 680+ historical DeFi exploits for pattern matching.
Follows Anthropic SCONE-bench approach.

ENHANCED: Now parses vulnerability types from README and file comments
to provide accurate categorization from 680+ real hacks.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime


# ============================================================================
# COMPREHENSIVE VULNERABILITY TYPE MAPPING (from README analysis)
# ============================================================================

VULNERABILITY_TYPE_MAPPING = {
    # Reentrancy variants
    "reentrancy": "reentrancy",
    "reentrant": "reentrancy", 
    "re-entrancy": "reentrancy",
    "read-only reentrancy": "reentrancy_readonly",
    
    # Price/Oracle manipulation
    "price manipulation": "price_manipulation",
    "price oracle manipulation": "oracle_manipulation",
    "oracle manipulation": "oracle_manipulation",
    "oracle": "oracle_manipulation",
    "twap": "oracle_twap",
    "bad oracle": "oracle_stale",
    "faulty oracle": "oracle_stale",
    "oracle bad price": "oracle_stale",
    "price out of date": "oracle_stale",
    "share price manipulation": "share_price_manipulation",
    "vulnerable price dependency": "price_manipulation",
    "overpriced asset": "oracle_manipulation",
    
    # Flash loan attacks
    "flashloan": "flashloan",
    "flash loan": "flashloan",
    "flashloan attack": "flashloan",
    "flashloan price oracle manipulation": "flashloan_oracle",
    
    # Access control
    "access control": "access_control",
    "lack of access control": "access_control",
    "incorrect access control": "access_control",
    "bad access control": "access_control",
    "unprotected function": "access_control",
    "missing access control": "access_control",
    
    # Logic flaws
    "logic flaw": "logic_flaw",
    "business logic flaw": "logic_flaw",
    "logic error": "logic_flaw",
    
    # Input validation
    "incorrect input validation": "input_validation",
    "improper input validation": "input_validation",
    "invalid signature verification": "signature_validation",
    "signature malleability": "signature_validation",
    "lack of validation": "input_validation",
    "insufficient validation": "input_validation",
    "unverified external call": "arbitrary_call",
    "arbitrary external call": "arbitrary_call",
    "arbitrary call": "arbitrary_call",
    "arbitrary user input": "input_validation",
    
    # Math errors
    "overflow": "integer_overflow",
    "underflow": "integer_underflow",
    "integer overflow": "integer_overflow",
    "integer underflow": "integer_underflow",
    "integer truncation": "precision_loss",
    "precision loss": "precision_loss",
    "loss of precision": "precision_loss",
    "precision truncation": "precision_loss",
    "unsafe math": "math_error",
    "unsafecast": "math_error",
    "unit mismatch": "math_error",
    
    # Reward/Fee issues
    "incorrect reward calculation": "reward_manipulation",
    "incorrect dividends": "reward_manipulation",
    "incorrect dividends calculation": "reward_manipulation",
    "incorrect fee logic": "fee_manipulation",
    "incorrect burn logic": "burn_manipulation",
    "incorrect token burn mechanism": "burn_manipulation",
    "claim rewards without protection": "reward_manipulation",
    "reward distribution problem": "reward_manipulation",
    
    # Slippage/MEV
    "not slippage protection": "missing_slippage",
    "lack of slippage protection": "missing_slippage",
    "no slippage protection": "missing_slippage",
    "sandwich attack": "sandwich_attack",
    "sandwich": "sandwich_attack",
    "mev": "mev_attack",
    "frontrun": "frontrunning",
    
    # Token-specific
    "deflationary token": "deflationary_token",
    "pair balance manipulation": "pair_manipulation",
    "pair manipulation": "pair_manipulation",
    "self transfer": "self_transfer",
    "token balance doubles": "self_transfer",
    
    # Proxy/Upgrade
    "uninitialized proxy": "uninitialized_proxy",
    "storage slot collision": "storage_collision",
    "storage slot1 collision": "storage_collision",
    
    # Miscellaneous
    "rug pull": "rug_pull",
    "phishing attack": "phishing",
    "weak random": "weak_randomness",
    "weak rng": "weak_randomness",
    "free mint": "free_mint",
    "misconfiguration": "misconfiguration",
    "post insolvency check": "insolvency_check",
    "bypassed insolvency check": "insolvency_check",
    "arbitrage": "arbitrage",
}


def normalize_vulnerability_type(raw_type: str) -> str:
    """
    Normalize vulnerability type from various formats.
    
    Args:
        raw_type: Raw vulnerability type string
        
    Returns:
        Normalized vulnerability type
    """
    raw_lower = raw_type.lower().strip()
    
    # Direct match
    if raw_lower in VULNERABILITY_TYPE_MAPPING:
        return VULNERABILITY_TYPE_MAPPING[raw_lower]
    
    # Partial match
    for pattern, vuln_type in VULNERABILITY_TYPE_MAPPING.items():
        if pattern in raw_lower:
            return vuln_type
    
    # Default
    return raw_type.lower().replace(" ", "_").replace("-", "_")


@dataclass
class ExploitRecord:
    """Record of a historical DeFi exploit."""
    id: str
    name: str
    date: datetime
    chain: str
    file_path: str
    vulnerability_type: str
    vulnerability_raw: str  # Original description from README
    description: str
    dollar_value: Optional[float] = None
    contracts: List[str] = None
    tx_hash: Optional[str] = None
    attacker_address: Optional[str] = None
    lost_amount: Optional[str] = None
    
    def __post_init__(self):
        if self.contracts is None:
            self.contracts = []


class DefiHackLabsDB:
    """Database of historical DeFi exploits from DefiHackLabs repository."""
    
    def __init__(self, repo_path: str = "/home/grey/Desktop/bugbounty/DeFiHackLabs"):
        self.repo_path = Path(repo_path)
        self.exploits: List[ExploitRecord] = []
        self.index: Dict[str, ExploitRecord] = {}
        self._readme_index: Dict[str, Dict] = {}  # name -> info from README
        
    def parse_exploits(self) -> List[ExploitRecord]:
        """
        Parse all exploit files from repository.
        
        Returns:
            List of ExploitRecord objects
        """
        # First, parse README for accurate vulnerability types
        self._parse_readme_index()
        
        test_dir = self.repo_path / "src" / "test"
        
        if not test_dir.exists():
            print(f"Warning: Test directory not found: {test_dir}")
            return []
        
        # Find all exploit files
        exploit_files = list(test_dir.rglob("*_exp.sol"))
        
        print(f"Found {len(exploit_files)} exploit files")
        print(f"README index contains {len(self._readme_index)} entries")
        
        for file_path in exploit_files:
            try:
                record = self._parse_exploit_file(file_path)
                if record:
                    self.exploits.append(record)
                    self.index[record.id] = record
            except Exception as e:
                print(f"Error parsing {file_path.name}: {e}")
        
        print(f"Successfully parsed {len(self.exploits)} exploits")
        return self.exploits
    
    def _parse_readme_index(self):
        """Parse README.md to get accurate vulnerability types."""
        readme_path = self.repo_path / "README.md"
        if not readme_path.exists():
            return
        
        content = readme_path.read_text()
        
        # Pattern: [20240101 Name](link#anchor---vulnerability-type)
        # or: [20240101 Name](#20240101-name---vulnerability-type)
        patterns = [
            r'\[(\d{8})\s+([^\]]+)\]\([^)]*#[^)]*---([^)]+)\)',
            r'\[(\d{8})\s+([^\]]+)\].*?---\s*([^\n\]]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                date_str, name, vuln_type = match
                name_key = name.strip().lower().replace(" ", "").replace("_", "")
                
                self._readme_index[name_key] = {
                    "date": date_str,
                    "name": name.strip(),
                    "vulnerability_raw": vuln_type.strip(),
                    "vulnerability_type": normalize_vulnerability_type(vuln_type),
                }
        
    def _parse_exploit_file(self, file_path: Path) -> Optional[ExploitRecord]:
        """Parse a single exploit file."""
        try:
            content = file_path.read_text()
            
            # Extract date from folder structure (e.g., 2025-01)
            parts = file_path.parts
            date_folder = None
            for part in parts:
                if re.match(r'202\d-\d{2}', part):
                    date_folder = part
                    break
            
            if date_folder:
                year, month = date_folder.split('-')
                date = datetime(int(year), int(month), 1)
            else:
                date = datetime.now()
            
            # Extract contract name
            name = file_path.stem.replace('_exp', '')
            name_key = name.lower().replace(" ", "").replace("_", "")
            
            # Create ID
            exploit_id = f"{date.strftime('%Y%m')}-{name}"
            
            # Check README index for accurate vulnerability type
            readme_info = self._readme_index.get(name_key, {})
            vuln_type = readme_info.get("vulnerability_type", self._detect_vulnerability_type(content))
            vuln_raw = readme_info.get("vulnerability_raw", "")
            
            # Extract chain (look for common markers)
            chain = self._detect_chain(content)
            
            # Extract contract addresses
            contracts = self._extract_addresses(content)
            
            # Extract description (from comments)
            description = self._extract_description(content)
            
            # Extract lost amount if mentioned
            lost_amount = self._extract_lost_amount(content)
            
            # Extract tx hash
            tx_hash = self._extract_tx_hash(content)
            
            # Extract attacker address
            attacker = self._extract_attacker(content)
            
            return ExploitRecord(
                id=exploit_id,
                name=name,
                date=date,
                chain=chain,
                file_path=str(file_path),
                vulnerability_type=vuln_type,
                vulnerability_raw=vuln_raw,
                description=description,
                contracts=contracts,
                tx_hash=tx_hash,
                attacker_address=attacker,
                lost_amount=lost_amount,
            )
            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None
    
    def _detect_chain(self, content: str) -> str:
        """Detect blockchain from code patterns."""
        content_lower = content.lower()
        
        chain_patterns = {
            "bsc": ["bsc", "binance", "pancake", "bnb"],
            "polygon": ["polygon", "matic", "quickswap"],
            "arbitrum": ["arbitrum", "arb", "arbiscan"],
            "optimism": ["optimism", "op_", "optimistic"],
            "avalanche": ["avalanche", "avax", "traderjoe"],
            "base": ["base", "basescan"],
            "fantom": ["fantom", "ftm", "spookyswap"],
        }
        
        for chain, patterns in chain_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    return chain
        
        return "ethereum"  # default
    
    def _detect_vulnerability_type(self, content: str) -> str:
        """Detect vulnerability type from code patterns."""
        content_lower = content.lower()
        
        # Check file comments first
        comment_patterns = {
            "reentrancy": ["reentrancy", "reentrant", "re-enter"],
            "flashloan": ["flashloan", "flash loan", "flashbots"],
            "oracle_manipulation": ["oracle", "price manipulation", "twap"],
            "access_control": ["access control", "onlyowner", "unauthorized"],
            "integer_overflow": ["overflow", "underflow", "unchecked"],
            "precision_loss": ["precision", "rounding", "truncat"],
            "signature_validation": ["signature", "ecrecover", "replay"],
            "logic_flaw": ["logic flaw", "business logic"],
            "rug_pull": ["rug pull", "rugpull"],
        }
        
        for vuln_type, patterns in comment_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    return vuln_type
        
        return "unknown"
    
    def _extract_addresses(self, content: str) -> List[str]:
        """Extract Ethereum addresses from code."""
        pattern = r'0x[a-fA-F0-9]{40}'
        addresses = re.findall(pattern, content)
        return list(set(addresses))[:10]
    
    def _extract_description(self, content: str) -> str:
        """Extract description from comments."""
        lines = content.split('\n')
        desc_lines = []
        
        for line in lines[:30]:
            line = line.strip()
            if line.startswith('//') or line.startswith('*'):
                cleaned = line.lstrip('/*').strip()
                if len(cleaned) > 10:
                    desc_lines.append(cleaned)
        
        if desc_lines:
            return ' '.join(desc_lines[:5])
        
        return "No description available"
    
    def _extract_lost_amount(self, content: str) -> Optional[str]:
        """Extract lost amount from comments."""
        patterns = [
            r'Total Lost\s*[:\-]?\s*~?\$?([\d,\.]+\s*[mMkK]?)',
            r'Lost\s*[:\-]?\s*~?\$?([\d,\.]+\s*[mMkK]?)',
            r'\$([\d,\.]+)\s*(?:million|m\b)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_tx_hash(self, content: str) -> Optional[str]:
        """Extract transaction hash from comments."""
        pattern = r'0x[a-fA-F0-9]{64}'
        match = re.search(pattern, content)
        return match.group(0) if match else None
    
    def _extract_attacker(self, content: str) -> Optional[str]:
        """Extract attacker address from comments."""
        pattern = r'Attacker\s*[:\-]?\s*(0x[a-fA-F0-9]{40})'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else None
    
    def find_similar(
        self,
        vulnerability_type: str,
        limit: int = 5
    ) -> List[ExploitRecord]:
        """
        Find similar exploits by vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability
            limit: Maximum number of results
            
        Returns:
            List of similar exploits
        """
        normalized = normalize_vulnerability_type(vulnerability_type)
        
        similar = [
            exploit for exploit in self.exploits
            if exploit.vulnerability_type == normalized
            or vulnerability_type.lower() in exploit.vulnerability_type.lower()
            or vulnerability_type.lower() in exploit.vulnerability_raw.lower()
        ]
        
        # Sort by date (most recent first)
        similar.sort(key=lambda x: x.date, reverse=True)
        
        return similar[:limit]
    
    def find_by_pattern(self, pattern: str, limit: int = 10) -> List[ExploitRecord]:
        """
        Find exploits matching a pattern in name or description.
        
        Args:
            pattern: Search pattern (regex)
            limit: Maximum results
            
        Returns:
            List of matching exploits
        """
        regex = re.compile(pattern, re.IGNORECASE)
        matches = []
        
        for exploit in self.exploits:
            if (regex.search(exploit.name) or 
                regex.search(exploit.description) or
                regex.search(exploit.vulnerability_raw)):
                matches.append(exploit)
        
        return matches[:limit]
    
    def get_by_name(self, name: str) -> Optional[ExploitRecord]:
        """Get exploit by name."""
        for exploit in self.exploits:
            if name.lower() in exploit.name.lower():
                return exploit
        return None
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        vuln_counts: Dict[str, int] = {}
        chain_counts: Dict[str, int] = {}
        year_counts: Dict[int, int] = {}
        
        for exploit in self.exploits:
            vuln_counts[exploit.vulnerability_type] = vuln_counts.get(exploit.vulnerability_type, 0) + 1
            chain_counts[exploit.chain] = chain_counts.get(exploit.chain, 0) + 1
            year_counts[exploit.date.year] = year_counts.get(exploit.date.year, 0) + 1
        
        # Sort by count
        vuln_counts = dict(sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True))
        
        return {
            "total_exploits": len(self.exploits),
            "vulnerability_types": vuln_counts,
            "chains": chain_counts,
            "by_year": dict(sorted(year_counts.items())),
            "date_range": {
                "earliest": min((e.date for e in self.exploits), default=None),
                "latest": max((e.date for e in self.exploits), default=None)
            }
        }
    
    def get_exploit_code(self, exploit_id: str) -> Optional[str]:
        """Get the source code of an exploit."""
        exploit = self.index.get(exploit_id)
        if exploit and Path(exploit.file_path).exists():
            return Path(exploit.file_path).read_text()
        return None
    
    def save_index(self, output_path: str = "exploit_index.json"):
        """Save index to JSON file."""
        data = [asdict(exploit) for exploit in self.exploits]
        
        for item in data:
            item['date'] = item['date'].isoformat()
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Saved {len(data)} exploits to {output_path}")
    
    def load_index(self, input_path: str = "exploit_index.json"):
        """Load index from JSON file."""
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        self.exploits = []
        for item in data:
            item['date'] = datetime.fromisoformat(item['date'])
            record = ExploitRecord(**item)
            self.exploits.append(record)
            self.index[record.id] = record
        
        print(f"Loaded {len(self.exploits)} exploits from {input_path}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def build_exploit_database(repo_path: str = "/home/grey/Desktop/bugbounty/DeFiHackLabs") -> DefiHackLabsDB:
    """Build and return exploit database."""
    db = DefiHackLabsDB(repo_path)
    db.parse_exploits()
    return db


def get_vulnerability_type_list() -> List[str]:
    """Get list of all vulnerability types we can detect."""
    return sorted(set(VULNERABILITY_TYPE_MAPPING.values()))


def search_exploits_by_vuln(vuln_type: str, limit: int = 5) -> List[ExploitRecord]:
    """Quick search for exploits by vulnerability type."""
    db = build_exploit_database()
    return db.find_similar(vuln_type, limit)


if __name__ == "__main__":
    # Test the database
    db = build_exploit_database()
    stats = db.get_statistics()
    
    print("\n" + "=" * 60)
    print("DEFIHACKLABS DATABASE STATISTICS")
    print("=" * 60)
    print(f"Total Exploits: {stats['total_exploits']}")
    print(f"\nBy Vulnerability Type:")
    for vuln, count in list(stats['vulnerability_types'].items())[:15]:
        print(f"  {vuln}: {count}")
    print(f"\nBy Chain:")
    for chain, count in stats['chains'].items():
        print(f"  {chain}: {count}")
    print(f"\nBy Year:")
    for year, count in stats['by_year'].items():
        print(f"  {year}: {count}")

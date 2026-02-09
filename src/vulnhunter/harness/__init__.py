"""
Harness Module - SCONE-bench Style Evaluation

Components:
- ExploitValidator: Validates profit extraction (≥0.1 ETH)
- DockerHarness: Sandboxed execution environment (future)
"""

from .exploit_validator import ExploitValidator

__all__ = [
    "ExploitValidator",
]

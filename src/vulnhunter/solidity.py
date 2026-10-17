"""Source structure extraction with comment/string masking and balanced braces.

This is a context builder, not a Solidity compiler or a sound static analyzer.
"""

import re
from dataclasses import dataclass


def mask_noncode(source: str, *, strings: bool = True) -> str:
    pattern = r"//[^\n]*|/\*[\s\S]*?\*/"
    if strings:
        pattern += r"""|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*' """.rstrip()
    return re.sub(
        pattern, lambda m: "".join("\n" if c == "\n" else " " for c in m[0]), source
    )


@dataclass
class SolidityFunction:
    name: str
    signature: str
    body: str
    start: int
    end: int
    line: int


def functions(source: str) -> list[SolidityFunction]:
    masked = mask_noncode(source)
    result = []
    for match in re.finditer(
        r"\b(function\s+(\w+)|constructor|receive|fallback)\s*\(", masked
    ):
        start = match.start()
        opening = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        if opening < 0 or (0 <= semicolon < opening):
            continue  # Interface declaration.
        depth, end = 1, opening + 1
        while depth and end < len(masked):
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        if depth:
            continue
        result.append(
            SolidityFunction(
                match.group(2) or match.group(1),
                source[start:opening],
                source[opening + 1 : end - 1],
                start,
                end,
                source[:start].count("\n") + 1,
            )
        )
    return result

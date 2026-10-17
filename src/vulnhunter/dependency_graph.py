"""Snapshot-based import relationships and bounded related-source context."""

import posixpath
import re

from .solidity import mask_noncode

_IMPORT = re.compile(r"\bimport\s+(?:[^;]*?\bfrom\s+)?[\"']([^\"']+)[\"']", re.DOTALL)
MAX_RELATED_FILES = 4
MAX_RELATED_CHARS = 60_000


def build_import_graph(sources: dict[str, str]) -> dict:
    """Resolve imports only against the immutable audited source snapshot."""
    imports: dict[str, list[str]] = {}
    imported_by: dict[str, list[str]] = {path: [] for path in sources}
    external: dict[str, list[str]] = {}
    for path, source in sources.items():
        dependencies: set[str] = set()
        unresolved: set[str] = set()
        for match in _IMPORT.finditer(mask_noncode(source, strings=False)):
            name = match.group(1)
            candidate = (
                posixpath.normpath(posixpath.join(posixpath.dirname(path), name))
                if name.startswith(".")
                else posixpath.normpath(name)
            )
            if candidate in sources:
                dependencies.add(candidate)
            else:
                unresolved.add(name)
        imports[path] = sorted(dependencies)
        external[path] = sorted(unresolved)
        for dependency in dependencies:
            imported_by[dependency].append(path)
    return {
        "imports": imports,
        "imported_by": {path: sorted(users) for path, users in imported_by.items()},
        "external_or_out_of_scope": external,
    }


def related_context(
    path: str,
    sources: dict[str, str],
    graph: dict,
    *,
    max_chars: int = MAX_RELATED_CHARS,
    max_files: int = MAX_RELATED_FILES,
) -> tuple[str, dict]:
    """Include direct imports and callers while recording every budget omission."""
    dependencies = graph["imports"][path]
    callers = graph["imported_by"][path]
    related = list(dict.fromkeys([*dependencies, *callers]))
    included: list[str] = []
    omitted: list[str] = []
    chunks: list[str] = []
    used = 0
    for candidate in related:
        chunk = f"\nRELATED FILE {candidate}\n{sources[candidate]}\n"
        if len(included) >= max_files or used + len(chunk) > max_chars:
            omitted.append(candidate)
            continue
        chunks.append(chunk)
        included.append(candidate)
        used += len(chunk)
    return "".join(chunks), {
        "included": included,
        "omitted": omitted,
        "related_chars": used,
        "external_or_out_of_scope": graph["external_or_out_of_scope"][path],
    }

"""Explainable Solidity scope discovery for a contract or a repository."""

import os
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 support.
    import tomli as tomllib

from .solidity import mask_noncode

PROJECT_MARKERS = (
    "foundry.toml",
    "hardhat.config.ts",
    "hardhat.config.js",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
    "truffle-config.js",
    "brownie-config.yaml",
    "ape-config.yaml",
    ".git",
)
GENERATED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "out",
    "artifacts",
    "cache",
    "build",
    "dist",
    "coverage",
    "broadcast",
}
VENDOR_DIRS = {"lib", "node_modules", "vendor", "third_party", "dependencies"}
TEST_DIRS = {"test", "tests", "testing", "spec", "specs"}
SCRIPT_DIRS = {"script", "scripts", "deploy", "deployments", "migrations"}
MOCK_DIRS = {"mock", "mocks", "fixture", "fixtures", "example", "examples"}
MAX_CANDIDATES = 20_000
_IMPORT = re.compile(r"\bimport\s+(?:[^;]*?\bfrom\s+)?[\"']([^\"']+)[\"']", re.DOTALL)


def project_root(target: Path) -> Path:
    target = target.resolve(strict=True)
    if target.is_dir():
        return target
    if target.suffix.lower() != ".sol":
        raise ValueError("Audit target must be a Solidity file or project directory")
    for parent in target.parents:
        if any((parent / marker).exists() for marker in PROJECT_MARKERS):
            return parent
    return target.parent


def _inventory(root: Path, *, include_vendor: bool) -> tuple[dict[str, Path], list[dict]]:
    found: dict[str, Path] = {}
    ignored = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        kept = []
        for name in sorted(dirs):
            child = base / name
            if child.is_symlink():
                reason = "symlink directory"
            elif name.lower() in GENERATED_DIRS:
                reason = "generated or environment directory"
            elif not include_vendor and name.lower() in VENDOR_DIRS:
                reason = "vendored dependency directory"
            elif not include_vendor and (child / ".git").exists():
                reason = "nested repository"
            else:
                reason = None
            if reason is None:
                kept.append(name)
            else:
                ignored.append({"path": child.relative_to(root).as_posix(), "reason": reason})
        dirs[:] = kept
        for name in sorted(files):
            if not name.lower().endswith(".sol"):
                continue
            path = base / name
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file():
                ignored.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "reason": "symlink escape or invalid file",
                    }
                )
                continue
            found[resolved.relative_to(root).as_posix()] = resolved
            if len(found) > MAX_CANDIDATES:
                raise ValueError(f"Repository exceeds {MAX_CANDIDATES} Solidity candidates")
    return found, ignored


def _configured_path(root: Path, value: str) -> str:
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Configured source path escapes project: {value}")
    return path.relative_to(root).as_posix()


def _under(relative: str, directory: str) -> bool:
    return directory == "." or relative == directory or relative.startswith(directory + "/")


def _source_layout(root: Path) -> tuple[set[str], set[str], list[str]]:
    """Read literal source paths without executing project configuration."""
    source_roots = {name for name in ("src", "contracts") if (root / name).is_dir()}
    auxiliary_roots: set[str] = set()
    notes = []
    foundry = root / "foundry.toml"
    if foundry.is_file():
        config = tomllib.loads(foundry.read_text(encoding="utf-8"))
        profiles = config.get("profile", {})
        active = os.environ.get("FOUNDRY_PROFILE", "default")
        profile = {**profiles.get("default", {}), **profiles.get(active, {})}
        source = profile.get("src", "src")
        if isinstance(source, str) and source.strip():
            source_roots = {_configured_path(root, source)}
        for field in ("test", "script"):
            path = profile.get(field)
            if isinstance(path, str) and path.strip():
                auxiliary_roots.add(_configured_path(root, path))
    else:
        hardhat = next(
            (
                root / name
                for name in (
                    "hardhat.config.ts",
                    "hardhat.config.js",
                    "hardhat.config.cjs",
                    "hardhat.config.mjs",
                )
                if (root / name).is_file()
            ),
            None,
        )
        if hardhat:
            source_roots = {"contracts"}
            config_text = hardhat.read_text(encoding="utf-8")
            paths = re.search(r"\bpaths\s*:\s*\{([^}]+)\}", config_text, re.DOTALL)
            if paths:
                for field in ("sources", "tests"):
                    value = re.search(rf"\b{field}\s*:\s*[\"']([^\"']+)[\"']", paths.group(1))
                    if value:
                        path = _configured_path(root, value.group(1))
                        if field == "sources":
                            source_roots = {path}
                        else:
                            auxiliary_roots.add(path)
                    elif field == "sources" and re.search(r"\bsources\s*:", paths.group(1)):
                        notes.append(
                            "Dynamic Hardhat sources path could not be resolved; review scope or use --scope full."
                        )
    return source_roots, auxiliary_roots, notes


def _category(relative: str, source_roots: set[str], auxiliary_roots: set[str]) -> str:
    path = Path(relative)
    parts = {part.lower() for part in path.parts[:-1]}
    stem = path.stem.lower()
    if any(_under(relative, root) for root in auxiliary_roots):
        return "test or deployment path from project config"
    if parts & VENDOR_DIRS:
        return "vendored dependency"
    if parts & TEST_DIRS or path.name.lower().endswith(".t.sol"):
        return "test"
    if parts & SCRIPT_DIRS or path.name.lower().endswith(".s.sol"):
        return "deployment script"
    if parts & MOCK_DIRS or stem.startswith("mock"):
        return "mock or example"
    if (
        source_roots
        and not any(_under(relative, root) for root in source_roots)
        and len(path.parts) > 1
    ):
        return "outside production source roots"
    return "production source"


def _explicit_files(root: Path, scope_file: Path) -> set[str]:
    selected: set[str] = set()
    for line in scope_file.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if any(character in entry for character in "*?[]"):
            raise ValueError("scope.txt requires explicit file or directory paths")
        candidate = (root / entry).resolve(strict=True)
        if not candidate.is_relative_to(root):
            raise ValueError(f"Scope path escapes project: {entry}")
        paths = candidate.rglob("*.sol") if candidate.is_dir() else [candidate]
        for path in paths:
            resolved = path.resolve(strict=True)
            if (
                not resolved.is_relative_to(root)
                or not resolved.is_file()
                or resolved.suffix.lower() != ".sol"
            ):
                raise ValueError(f"Invalid scope path: {entry}")
            selected.add(resolved.relative_to(root).as_posix())
    if not selected:
        raise ValueError("No Solidity files found in audit scope")
    return selected


def _local_imports(
    root: Path, relative: str, inventory: dict[str, Path], *, discover_missing: bool = False
) -> set[str]:
    source = inventory[relative]
    if source.stat().st_size > 500_000:
        return set()
    masked = mask_noncode(source.read_text(encoding="utf-8"), strings=False)
    imports = set()
    for match in _IMPORT.finditer(masked):
        name = match.group(1)
        if name.startswith("."):
            candidate = (source.parent / name).resolve()
        else:
            candidate = (root / name).resolve()
        if not candidate.is_relative_to(root):
            continue
        key = candidate.relative_to(root).as_posix()
        if (
            discover_missing
            and key not in inventory
            and candidate.is_file()
            and candidate.suffix.lower() == ".sol"
        ):
            parts = {part.lower() for part in candidate.relative_to(root).parts[:-1]}
            if not parts & (VENDOR_DIRS | GENERATED_DIRS):
                inventory[key] = candidate
                if len(inventory) > MAX_CANDIDATES:
                    raise ValueError("Import graph exceeds Solidity candidate limit")
        if key in inventory:
            imports.add(key)
    return imports


def plan_scope(target: Path, mode: str = "default") -> dict:
    """Return a bounded, reviewable decision for every discovered Solidity file."""
    if mode not in {"default", "auto", "full", "explicit"}:
        raise ValueError("Scope mode must be default, auto, full, or explicit")
    target = target.resolve(strict=True)
    root = project_root(target)
    scope_file = root / "scope.txt"
    resolved_mode = (
        "file"
        if target.is_file() and mode == "default"
        else (
            "explicit"
            if mode == "default" and scope_file.is_file()
            else "auto" if mode == "default" else mode
        )
    )
    if resolved_mode == "explicit" and not scope_file.is_file():
        raise ValueError("--scope explicit requires scope.txt in the project root")
    notes = []
    if resolved_mode == "file":
        key = target.relative_to(root).as_posix()
        inventory, ignored = {key: target}, []
        notes.append(
            "Other repository files are outside this focused contract scan and were not enumerated."
        )
    elif resolved_mode == "explicit":
        selected = _explicit_files(root, scope_file)
        inventory, ignored = {name: root / name for name in selected}, []
        notes.append("scope.txt is authoritative; unlisted repository files were not enumerated.")
    else:
        inventory, ignored = _inventory(root, include_vendor=resolved_mode in {"full", "explicit"})
        if target.is_file():
            key = target.relative_to(root).as_posix()
            inventory[key] = target
    if not inventory:
        raise ValueError("No Solidity files found in project")
    if resolved_mode == "auto":
        source_roots, auxiliary_roots, layout_notes = _source_layout(root)
        notes.extend(layout_notes)
    else:
        source_roots, auxiliary_roots = set(), set()
    reason: dict[str, str] = {}
    if resolved_mode == "full":
        reason = {name: "full repository override" for name in inventory}
    elif resolved_mode == "explicit":
        reason = {name: "listed in scope.txt" for name in selected}
    elif resolved_mode == "file":
        reason = {target.relative_to(root).as_posix(): "requested contract"}
    else:
        reason = {
            name: "production source"
            for name in inventory
            if _category(name, source_roots, auxiliary_roots) == "production source"
        }
    if resolved_mode in {"auto", "file"}:
        queue = list(reason)
        while queue:
            parent = queue.pop()
            for dependency in _local_imports(
                root, parent, inventory, discover_missing=resolved_mode == "file"
            ):
                if dependency not in reason:
                    reason[dependency] = f"local import of {parent}"
                    queue.append(dependency)
    if not reason:
        raise ValueError("No production Solidity files found; use --scope full or scope.txt")
    included = [{"file": name, "reason": reason[name]} for name in sorted(reason)]
    excluded = [
        {
            "file": name,
            "reason": _category(name, source_roots, auxiliary_roots),
        }
        for name in sorted(set(inventory) - set(reason))
    ]
    return {
        "root": root,
        "mode": resolved_mode,
        "target": target.relative_to(root).as_posix() if target.is_file() else None,
        "included": included,
        "excluded": excluded,
        "ignored_paths": sorted(ignored, key=lambda item: item["path"]),
        "notes": notes,
    }

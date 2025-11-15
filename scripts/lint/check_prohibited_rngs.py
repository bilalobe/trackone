#!/usr/bin/env python3
"""AST-based RNG policy checker (pre-commit/CI)

Detects insecure/non-cryptographic randomness usage:
  - random.* (rand*, randint, randrange, randbits, choice, random, seed)
  - Direct imports (from random import randint)
  - numpy.random.* via numpy/np or aliases
  - Aliased imports (import random as r, from numpy import random as nr)

Suppressions:
  - File-level: # allow-prohibited-rng
  - Line-level: # rng-ok

Exit 1 on findings, 0 otherwise.
"""
from __future__ import annotations

import ast
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

FILE_LEVEL_ALLOW = "allow-prohibited-rng"
LINE_LEVEL_ALLOW = "rng-ok"

# Standard library random module methods (insecure)
_RANDOM_MODULE_METHODS = {
    "randint",
    "randrange",
    "randbits",
    "choice",
    "random",
    "seed",
}

# NumPy-specific random methods (insecure)
_NUMPY_RANDOM_METHODS = {
    "rand",
    "randn",
    "randint",
    "choice",
    "random",
}

# Safe methods from random module (CSPRNG)
_RANDOM_MODULE_SAFE = {
    "SystemRandom",
}


@dataclass
class Finding:
    lineno: int
    kind: str
    detail: str
    line: str

    def format(self) -> str:
        return f"  {self.lineno}: {self.kind}: {self.detail}  ->  {self.line.rstrip()}"


# Import handling
def _handle_import(
    alias: ast.alias,
    random_aliases: set[str],
    numpy_aliases: set[str],
    numpy_random_aliases: set[str],
) -> None:
    root = alias.name
    # For dotted imports without alias, Python binds the first component
    # e.g., "import numpy.random" binds "numpy" in the namespace
    if alias.asname:
        asname = alias.asname
    elif "." in root:
        asname = root.split(".")[0]  # First component, not last
    else:
        asname = root

    if root == "random":
        random_aliases.add(asname)
    elif root == "numpy":
        numpy_aliases.add(asname)
    elif root == "numpy.random":
        # "import numpy.random" binds "numpy" not "random"
        numpy_aliases.add(asname)


def _handle_import_from(
    module: str,
    alias: ast.alias,
    numpy_random_aliases: set[str],
    random_direct_funcs: set[str],
    star_imports: set[str],
) -> None:
    # Handle star imports - flag the module as having a star import
    if alias.name == "*":
        star_imports.add(module)
        return

    if module == "random":
        # Skip safe CSPRNG methods like SystemRandom
        if alias.name in _RANDOM_MODULE_SAFE:
            return
        # Flag all other imports from random module
        random_direct_funcs.add(alias.asname or alias.name)
    elif module == "numpy.random":
        target = alias.asname or alias.name
        # Add as direct func if a well-known RNG function
        if alias.name in _NUMPY_RANDOM_METHODS:
            random_direct_funcs.add(target)
        else:
            numpy_random_aliases.add(target)
    elif module == "numpy" and alias.name == "random":
        target = alias.asname or alias.name
        numpy_random_aliases.add(target)


def _collect_import_aliases(
    node: ast.AST,
    random_aliases: set[str],
    numpy_aliases: set[str],
    numpy_random_aliases: set[str],
    random_direct_funcs: set[str],
    star_imports: set[str],
) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            _handle_import(alias, random_aliases, numpy_aliases, numpy_random_aliases)
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            _handle_import_from(
                module, alias, numpy_random_aliases, random_direct_funcs, star_imports
            )


# Analysis helpers


def _full_attr_chain(node: ast.Attribute) -> list[str]:
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value  # type: ignore[assignment]
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return list(reversed(parts))


def _is_random_call(chain: list[str], random_aliases: set[str]) -> bool:
    return (
        len(chain) >= 2
        and chain[0] in random_aliases
        and chain[-1] in _RANDOM_MODULE_METHODS
    )


def _is_numpy_random_call(
    chain: list[str], numpy_aliases: set[str], numpy_random_aliases: set[str]
) -> bool:
    if len(chain) >= 2:
        root = chain[0]
        # Check if it's numpy.random.* pattern
        if root in numpy_aliases and chain[1] == "random":
            return True
        # Check if it's an alias to numpy.random
        if root in numpy_random_aliases:
            return True
    return False


def _is_direct_func_call(func: ast.AST, random_direct_funcs: set[str]) -> bool:
    return isinstance(func, ast.Name) and func.id in random_direct_funcs


def _scan_star_imports(
    tree: ast.AST,
    lines: list[str],
    star_imports: set[str],
) -> list[Finding]:
    """Detect star imports from prohibited modules"""
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        ln = getattr(node, "lineno", None)
        if ln is None:
            continue
        module = node.module or ""
        if module not in star_imports:
            continue
        line = lines[ln - 1] if 0 <= ln - 1 < len(lines) else ""
        if LINE_LEVEL_ALLOW in line:
            continue
        findings.append(Finding(ln, "star-import", f"from {module} import *", line))
    return findings


def _scan_calls(
    tree: ast.AST,
    lines: list[str],
    random_aliases: set[str],
    numpy_aliases: set[str],
    numpy_random_aliases: set[str],
    random_direct_funcs: set[str],
    star_imports: set[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        ln = getattr(node, "lineno", None)
        if ln is None:
            continue
        line = lines[ln - 1] if 0 <= ln - 1 < len(lines) else ""
        if LINE_LEVEL_ALLOW in line:
            continue
        chain: list[str] = []
        if isinstance(node.func, ast.Attribute):
            chain = _full_attr_chain(node.func)
        if chain and _is_random_call(chain, random_aliases):
            findings.append(Finding(ln, "random-call", ".".join(chain), line))
            continue
        if chain and _is_numpy_random_call(chain, numpy_aliases, numpy_random_aliases):
            findings.append(Finding(ln, "numpy-random-call", ".".join(chain), line))
            continue
        if _is_direct_func_call(node.func, random_direct_funcs):  # type: ignore[arg-type]
            findings.append(
                Finding(ln, "random-func", getattr(node.func, "id", "<unknown>"), line)
            )
            continue
        # Check for potential star import usage
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Check if this could be from a star import of random module
            if "random" in star_imports and func_name in _RANDOM_MODULE_METHODS:
                findings.append(
                    Finding(ln, "star-import-call", f"{func_name} (from random.*)", line)
                )
                continue
            # Check if this could be from a star import of numpy.random
            if "numpy.random" in star_imports and func_name in _NUMPY_RANDOM_METHODS:
                findings.append(
                    Finding(ln, "star-import-call", f"{func_name} (from numpy.random.*)", line)
                )
    return findings


# Public API


def analyze(path: Path) -> list[Finding]:
    text = path.read_text(encoding="utf8")
    if FILE_LEVEL_ALLOW in text:
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []
    random_aliases: set[str] = {"random"}
    numpy_aliases: set[str] = {"numpy"}
    numpy_random_aliases: set[str] = set()
    random_direct_funcs: set[str] = set()
    star_imports: set[str] = set()
    for node in ast.walk(tree):
        _collect_import_aliases(
            node,
            random_aliases,
            numpy_aliases,
            numpy_random_aliases,
            random_direct_funcs,
            star_imports,
        )
    lines = text.splitlines()
    findings = _scan_calls(
        tree,
        lines,
        random_aliases,
        numpy_aliases,
        numpy_random_aliases,
        random_direct_funcs,
        star_imports,
    )
    # Add star import findings
    findings.extend(_scan_star_imports(tree, lines, star_imports))
    return findings


def check_path(path: Path) -> list[Finding]:
    if not path.exists() or path.suffix != ".py":
        return []
    return analyze(path)


def main(argv: Iterable[str] | None = None) -> int:
    files = list(argv or sys.argv[1:])
    if not files:
        print("No files given; nothing to check.")
        return 0
    any_found = False
    for f in files:
        p = Path(f)
        if p.suffix != ".py" or not p.exists():
            continue
        findings = check_path(p)
        if findings:
            any_found = True
            print(f"\n{p}: prohibited RNG usage detected:")
            for fd in findings:
                print(fd.format())
            print(
                "  Suggestion: use `secrets` or os.urandom; add '# rng-ok' for a single justified suppression or '# allow-prohibited-rng' for file-level justification."
            )
    if any_found:
        print(
            "\nProhibited RNG usage found. Replace insecure randomness or justify suppression."
        )
        return 1
    print("No prohibited RNG usage found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

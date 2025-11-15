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
_RANDOM_METHODS = {
    "rand",
    "randint",
    "randrange",
    "randbits",
    "choice",
    "random",
    "seed",
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
    asname = alias.asname or root.split(".")[-1]
    if root == "random":
        random_aliases.add(asname)
    elif root == "numpy":
        numpy_aliases.add(asname)
    elif root == "numpy.random":
        numpy_random_aliases.add(asname)


def _handle_import_from(
    module: str,
    alias: ast.alias,
    numpy_random_aliases: set[str],
    random_direct_funcs: set[str],
) -> None:
    if module == "random":
        random_direct_funcs.add(alias.asname or alias.name)
    elif module == "numpy.random":
        target = alias.asname or alias.name
        # Add as direct func if a well-known RNG function
        if alias.name in _RANDOM_METHODS or alias.name in {"rand", "randn"}:
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
) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            _handle_import(alias, random_aliases, numpy_aliases, numpy_random_aliases)
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            _handle_import_from(
                module, alias, numpy_random_aliases, random_direct_funcs
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
        len(chain) >= 2 and chain[0] in random_aliases and chain[-1] in _RANDOM_METHODS
    )


def _is_numpy_random_call(
    chain: list[str], numpy_aliases: set[str], numpy_random_aliases: set[str]
) -> bool:
    if len(chain) >= 2:
        root = chain[0]
        if (
            root in numpy_aliases
            and chain[1] == "random"
            and chain[-1] != "RandomState"
        ):
            return True
        if root in numpy_random_aliases:
            return True
    return False


def _is_direct_func_call(func: ast.AST, random_direct_funcs: set[str]) -> bool:
    return isinstance(func, ast.Name) and func.id in random_direct_funcs


def _scan_calls(
    tree: ast.AST,
    lines: list[str],
    random_aliases: set[str],
    numpy_aliases: set[str],
    numpy_random_aliases: set[str],
    random_direct_funcs: set[str],
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
    for node in ast.walk(tree):
        _collect_import_aliases(
            node,
            random_aliases,
            numpy_aliases,
            numpy_random_aliases,
            random_direct_funcs,
        )
    lines = text.splitlines()
    return _scan_calls(
        tree,
        lines,
        random_aliases,
        numpy_aliases,
        numpy_random_aliases,
        random_direct_funcs,
    )


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

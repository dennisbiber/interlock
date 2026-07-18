#!/usr/bin/env python3
"""Enforce interlock's zero-runtime-dependency invariant.

The PDP ships stdlib-only, and the JS PEP client uses only Node built-ins. This
is a deliberate trust property for a security component: fewer moving parts,
nothing to supply-chain-compromise in the enforcement path. CI fails if:

  1. pyproject [project].dependencies is non-empty.
  2. Any top-level import in the shipped `interlock/` package is not stdlib
     (or first-party). Test/dev-only imports are not checked.
  3. The OpenClaw adapter package.json declares runtime dependencies.

Run: python scripts/check_no_runtime_deps.py   (needs Python >= 3.11 for tomllib)
"""
from __future__ import annotations

import ast
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "interlock"
FIRST_PARTY = {"interlock"}
STDLIB = set(sys.stdlib_module_names)  # Python 3.10+

failures: list[str] = []


def check_pyproject() -> None:
    import tomllib  # 3.11+

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    deps = data.get("project", {}).get("dependencies", [])
    if deps:
        failures.append(f"pyproject declares runtime dependencies: {deps}")


def check_python_imports() -> None:
    for path in PKG.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m and m not in STDLIB and m not in FIRST_PARTY:
                    rel = path.relative_to(ROOT)
                    failures.append(f"non-stdlib runtime import {m!r} in {rel}")


def check_node_pkg() -> None:
    pkg = ROOT / "interlock" / "adapters" / "openclaw" / "package.json"
    if pkg.exists():
        data = json.loads(pkg.read_text())
        if data.get("dependencies"):
            failures.append(f"OpenClaw package.json declares deps: {data['dependencies']}")


def main() -> int:
    check_pyproject()
    check_python_imports()
    check_node_pkg()
    if failures:
        print("Zero-dependency check FAILED:")
        for f in sorted(set(failures)):
            print(f"  - {f}")
        return 1
    print("Zero-dependency check passed: PDP is stdlib-only, PEP client is Node-builtin-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Enforce interlock's zero-runtime-dependency invariant.

The PDP ships stdlib-only, and the JS PEP client uses only Node built-ins. This
is a deliberate trust property for a security component: fewer moving parts,
nothing to supply-chain-compromise in the enforcement path. CI fails if:

  1. pyproject [project].dependencies is non-empty.
  2. Any top-level import in the shipped `interlock/` package is not stdlib
     (or first-party). Test/dev-only imports are not checked.
  3. The OpenClaw adapter package.json declares runtime dependencies.
  4. Any dynamic `importlib.import_module("literal")` in `interlock/` names a
     module outside OPTIONAL_HARNESS_MODULES.

Check 4 exists because check 2 walks the AST and a dynamic import is invisible
to it. Adapters legitimately need to reach an OPTIONAL harness that interlock
does not depend on — interlock still installs and runs with zero dependencies,
and the harness is imported only if the user already has it. But that mechanism
would equally hide a real dependency, so every dynamic import must be declared
here and reviewed. A dynamic import of a non-stdlib module is only acceptable
when the module is a harness the adapter integrates WITH, never a library the
enforcement path relies ON.

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

#: Optional harness modules an adapter may import dynamically. Adding an entry
#: is a deliberate, reviewable act. Nothing in the enforcement path may depend
#: on any of these being present.
OPTIONAL_HARNESS_MODULES = {
    "hermes_cli.plugins",  # interlock/adapters/hermes/plugin.py
}

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


#: Marker an author puts on the same line as a genuinely runtime-determined
#: import_module() call. It cannot be checked mechanically, so it is checked
#: socially: the marker makes the call visible in review and in grep.
DYNAMIC_IMPORT_MARKER = "# dynamic-import:"


def _module_level_str_constants(tree: ast.Module) -> dict[str, str]:
    """Collect module-level NAME = "literal" bindings so they can be folded."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def check_dynamic_imports() -> None:
    """Flag importlib.import_module() targets that are not declared or marked."""
    for path in PKG.rglob("*.py"):
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        constants = _module_level_str_constants(tree)
        lines = source.splitlines()
        rel = path.relative_to(ROOT)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_import = (
                (isinstance(func, ast.Attribute) and func.attr == "import_module")
                or (isinstance(func, ast.Name) and func.id == "import_module")
            )
            if not is_import or not node.args:
                continue

            target = node.args[0]
            module = None
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                module = target.value
            elif isinstance(target, ast.Name) and target.id in constants:
                module = constants[target.id]

            if module is None:
                # Runtime-determined: cannot be resolved statically, so it must
                # carry a reviewed marker rather than passing silently. The
                # marker may sit on the call line or in the comment block
                # immediately above it, so the reason can be a real sentence.
                start = max(0, node.lineno - 4)
                window = "\n".join(lines[start:node.lineno])
                if DYNAMIC_IMPORT_MARKER not in window:
                    failures.append(
                        f"unmarked runtime-determined importlib.import_module() at "
                        f"{rel}:{node.lineno} (annotate with "
                        f"'{DYNAMIC_IMPORT_MARKER} <why this cannot be a dependency>')"
                    )
                continue

            root = module.split(".")[0]
            if root in STDLIB or root in FIRST_PARTY:
                continue
            if module not in OPTIONAL_HARNESS_MODULES:
                failures.append(
                    f"undeclared dynamic import {module!r} at {rel}:{node.lineno} "
                    "(add it to OPTIONAL_HARNESS_MODULES if it is an optional "
                    "harness, not a dependency)"
                )


def check_node_pkg() -> None:
    pkg = ROOT / "interlock" / "adapters" / "openclaw" / "package.json"
    if pkg.exists():
        data = json.loads(pkg.read_text())
        if data.get("dependencies"):
            failures.append(f"OpenClaw package.json declares deps: {data['dependencies']}")


def main() -> int:
    check_pyproject()
    check_python_imports()
    check_dynamic_imports()
    check_node_pkg()
    if failures:
        print("Zero-dependency check FAILED:")
        for f in sorted(set(failures)):
            print(f"  - {f}")
        return 1
    print("Zero-dependency check passed: PDP is stdlib-only, PEP client is Node-builtin-only,\n"
          "all dynamic imports declared.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

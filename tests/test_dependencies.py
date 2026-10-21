"""Every third-party import in ``app/`` must resolve to a declared distribution.

Why this file exists
--------------------
``validate_seed_phrase``, ``derive_addresses`` and ``convert_mnemonic`` all do
``from mnemonic import Mnemonic`` at call time, and ``derive_addresses`` also needs
``bech32``.  The package was installed in the developer's environment but was absent
from ``requirements.txt``, so the deployed virtualenv did not have it.  The result was
three endpoints returning ``500 internal_error`` in production while the whole test
suite stayed green -- the suite imports the same environment that has the package.

This test closes that gap: it statically enumerates every third-party import in the
package and asserts each one maps to a distribution listed in ``requirements.txt``.
It runs no application code and needs no network.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = PROJECT_ROOT / "app"
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"

#: import name -> distribution name, where the two differ.
#: Anything not listed here is assumed to share its distribution name.
IMPORT_TO_DIST = {
    "Crypto": "pycryptodome",
    "PIL": "pillow",
    "eth_keys": "eth-keys",
}

#: Distributions declared in requirements.txt that are legitimately not imported
#: anywhere in ``app/``.  ``pytest`` is test-only; ``requests`` is used by the
#: scripts/ and tools/ entry points, which the web app imports rather than inlining.
KNOWN_OPTIONAL = {"pytest", "requests"}


def _declared_distributions() -> set:
    """Distribution names declared in requirements.txt, normalised to lowercase."""
    names = set()
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for sep in (">=", "<=", "==", "~=", "!=", ">", "<"):
            line = line.split(sep, 1)[0]
        line = line.strip()
        if line:
            names.add(line.lower().replace("_", "-"))
    return names


def _third_party_imports() -> dict:
    """Map import name -> set of files that import it, for every module in ``app/``."""
    found: dict = {}
    for path in sorted(APP_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:      # pragma: no cover - guarded elsewhere by py_compile
            continue
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module.split(".")[0]]
            for name in modules:
                if name in sys.stdlib_module_names:
                    continue
                if name in ("app", "scripts", "tools"):
                    continue
                found.setdefault(name, set()).add(str(path.relative_to(PROJECT_ROOT)))
    return found


class TestRequirementsCoverImports:
    def test_app_imports_are_declared(self):
        """No third-party import in app/ may be missing from requirements.txt."""
        declared = _declared_distributions()
        undeclared = {}
        for name, files in sorted(_third_party_imports().items()):
            dist = IMPORT_TO_DIST.get(name, name).lower().replace("_", "-")
            if dist not in declared and dist not in KNOWN_OPTIONAL:
                undeclared[name] = sorted(files)

        assert not undeclared, (
            "these imports have no matching entry in requirements.txt, so the "
            "deployed virtualenv will not contain them and the endpoints that "
            "import them will fail at runtime:\n"
            + "\n".join(f"  {k:12s} -> {v}" for k, v in undeclared.items())
        )

    def test_critical_crypto_dependencies_are_declared(self):
        """The specific packages whose absence broke production must stay declared."""
        declared = _declared_distributions()
        for dist in ("mnemonic", "bech32", "pillow", "base58", "coincurve",
                     "pycryptodome", "eth-keys"):
            assert dist in declared, (
                f"{dist!r} is missing from requirements.txt -- it was the root "
                f"cause of the deployed 500s"
            )

    def test_declared_distributions_are_importable_names(self):
        """Each declared distribution maps back to a real import name we can find."""
        declared = _declared_distributions()
        imports = _third_party_imports()
        # Reverse map: for each declared dist, is there an import name for it?
        import_names = {IMPORT_TO_DIST.get(n, n).lower().replace("_", "-") for n in imports}
        import_names |= {n.lower() for n in imports}
        for dist in sorted(declared):
            assert dist in import_names or dist in KNOWN_OPTIONAL, (
                f"requirements.txt declares {dist!r} but no module in app/ imports it; "
                f"typo in the requirement name?"
            )


class TestRequirementsFileIsParseable:
    def test_requirements_file_exists(self):
        assert REQUIREMENTS.is_file(), f"missing {REQUIREMENTS}"

    def test_requirements_has_no_duplicate_distributions(self):
        seen, dupes = set(), set()
        for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            for sep in (">=", "<=", "==", "~=", "!=", ">", "<"):
                line = line.split(sep, 1)[0]
            name = line.strip().lower().replace("_", "-")
            if not name:
                continue
            (dupes if name in seen else seen).add(name)
        assert not dupes, f"duplicate distribution entries: {sorted(dupes)}"

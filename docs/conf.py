"""Sphinx configuration for the Mhook API reference."""

import pathlib
import re

project = "Mhook"
copyright = "2026, SToFU Systems"
author = "SToFU Systems"


def _read_version():
    """Reads the version out of the root CMakeLists.txt.

    The version lives in exactly one place. Duplicating it here would create a
    second copy that silently goes stale.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    text = (root / "CMakeLists.txt").read_text(encoding="utf-8")
    parts = []
    for component in ("MAJOR", "MINOR", "PATCH"):
        match = re.search(rf"set\(MHOOK_VERSION_{component}\s+(\d+)\)", text)
        if match is None:
            raise RuntimeError(f"MHOOK_VERSION_{component} not found in CMakeLists.txt")
        parts.append(match.group(1))
    return ".".join(parts)


release = _read_version()
version = ".".join(release.split(".")[:2])

extensions = ["breathe"]

breathe_projects = {"mhook": "../_docs/doxygen/xml"}
breathe_default_project = "mhook"
breathe_domain_by_extension = {"h": "c"}

html_theme = "alabaster"
html_title = f"Mhook {release}"

exclude_patterns = ["superpowers", "requirements.txt"]

# Every warning is a broken cross-reference or an undocumented public symbol.
nitpicky = True

# These come from windows.h, not from mhook.h, so Doxygen never sees a
# definition to cross-reference. Ignoring them here is not a workaround for a
# broken reference; the reference is correctly unresolvable, since Mhook does
# not document the Windows SDK.
nitpick_ignore = [
    ("c:identifier", "BOOL"),
    ("c:identifier", "PVOID"),
    ("c:identifier", "SIZE_T"),
]

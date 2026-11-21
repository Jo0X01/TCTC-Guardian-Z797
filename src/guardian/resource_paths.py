from __future__ import annotations

import sys
from pathlib import Path


def _nuitka_runtime_directory() -> Path | None:
    """Return the directory containing bundled Nuitka runtime resources."""
    try:
        compiled = __compiled__
    except NameError:
        return None

    runtime_dir = getattr(compiled, "python_runtime_dir", None)
    if not runtime_dir:
        return None

    try:
        return Path(runtime_dir).resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def resolve_resource(
    *relative_parts: str,
    executable_path: str | Path | None = None,
    package_file: str | Path = __file__,
) -> Path | None:
    """Find resources in source, Nuitka standalone, and Nuitka onefile layouts.

    Search priority:
    1. Nuitka runtime directory (bundled resources, including Onefile).
    2. Directory beside the executable (Standalone/external resources).
    3. Project root inferred from the package file (source development).
    """
    if not relative_parts:
        return None

    for part in relative_parts:
        candidate_part = Path(part)
        if candidate_part.is_absolute() or ".." in candidate_part.parts:
            return None

    roots: list[Path] = []

    runtime_root = _nuitka_runtime_directory()
    if runtime_root is not None:
        roots.append(runtime_root)

    executable = Path(
        executable_path if executable_path is not None else sys.argv[0]
    )
    try:
        roots.append(executable.resolve().parent)
    except (OSError, RuntimeError):
        pass

    try:
        roots.append(Path(package_file).resolve().parents[2])
    except (OSError, RuntimeError, IndexError):
        pass

    seen: set[str] = set()

    for base in roots:
        key = str(base).casefold()
        if key in seen:
            continue
        seen.add(key)

        candidate = base.joinpath(*relative_parts)

        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue

    return None
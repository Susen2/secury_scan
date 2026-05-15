import os
from pathlib import Path

DEFAULT_EXCLUDES = {
    "venv",
    ".venv",
    ".git",
    "__pycache__",
    ".tox",
    ".eggs",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "*.egg-info",
    ".idea",
    ".vscode",
    "test",
    "examples"
}


def _is_excluded(file_path: Path, exclude_patterns: set[str]) -> bool:
    parts = set(file_path.parts)
    return bool(parts & exclude_patterns)


def collect_files(root: str, exclude_dirs: set[str] | None = None) -> list[tuple[str, str]]:
    excludes = DEFAULT_EXCLUDES | (exclude_dirs or set())

    results: list[tuple[str, str]] = []
    root_path = Path(root).resolve()

    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root_path}")

    for dirpath, dirnames, filenames in os.walk(root_path):
        current = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in excludes]

        if _is_excluded(current, excludes):
            dirnames[:] = []
            continue

        for fname in filenames:
            if fname.endswith(".py"):
                file_path = current / fname
                try:
                    content = file_path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, PermissionError):
                    continue
                results.append((str(file_path), content))

    return results

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_PATHS = [
    "app",
    "VAELQORIX.XDR_COMMAND/src",
    "README.md",
    "docs",
    "tests",
    ".github",
    ".env.example",
    "scripts",
]

TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".jsx",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yml",
    ".yaml",
}

MOJIBAKE_MARKERS = ("\u00f0", "\u00c3", "\u00c2", "\u00e2", "\u00ef", "\ufffd")


def iter_text_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                child
                for child in path.rglob("*")
                if child.is_file() and child.suffix in TEXT_SUFFIXES
            )
    return sorted(set(files))


def find_mojibake(paths: list[str]) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in iter_text_files(paths):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as exc:
            findings.append((path, 0, f"invalid utf-8: {exc}"))
            continue

        for line_number, line in enumerate(lines, start=1):
            if any(marker in line for marker in MOJIBAKE_MARKERS) or any(
                0x80 <= ord(char) <= 0x9F for char in line
            ):
                findings.append((path, line_number, line.strip()))
    return findings


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Detect common mojibake markers in source text files."
    )
    parser.add_argument("paths", nargs="*", default=DEFAULT_PATHS)
    parser.add_argument(
        "--max-existing",
        type=int,
        default=0,
        help="Temporary baseline while legacy mojibake is cleaned up.",
    )
    parser.add_argument("--show-limit", type=int, default=30)
    args = parser.parse_args()

    findings = find_mojibake(args.paths)
    count = len(findings)

    if count <= args.max_existing:
        print(f"text encoding check passed: {count} findings within baseline {args.max_existing}")
        return 0

    print(
        f"text encoding check failed: {count} findings exceed baseline {args.max_existing}"
    )
    for path, line_number, text in findings[: args.show_limit]:
        print(f"{path}:{line_number}: {text}")
    if count > args.show_limit:
        print(f"... {count - args.show_limit} more findings")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

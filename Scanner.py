#!/usr/bin/env python3
"""
key_scanner.py – High‑performance, cross‑platform Base58 private‑key scanner.

Examples
--------
# basic
python key_scanner.py .

# quiet scan, print WIF, write keys to file
python key_scanner.py C:\Users\me\Downloads -q --show-wif -o keys.txt

# use 8 worker threads, ignore files > 20 MB
python key_scanner.py /data --workers 8 --max-size 20
"""
from __future__ import annotations

import argparse
import mmap
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Set

# ─────────────────────────── constants ──────────────────────────────
BASE58_PATTERN = rb'[13][a-km-zA-HJ-NP-Z0-9]{52}'
BASE58_REGEX = re.compile(BASE58_PATTERN)  # bytes regex

DEFAULT_WORKERS = max(4, (os.cpu_count() or 4) * 2)  # sensible IO default

# ─────────────────────────── helpers ────────────────────────────────
def validate_path(p: Path) -> bool:
    """Return True iff *p* exists and is a directory."""
    return p.is_dir()


def _scan_file(
    file_path: Path,
    *,
    quiet: bool,
    max_bytes: int | None,
) -> Set[str]:
    """Scan a single file, return any Base58 keys (as *str*) found."""
    keys: Set[str] = set()

    try:
        # Skip very large files when size limit is set
        if max_bytes is not None and file_path.stat().st_size > max_bytes:
            if not quiet:
                print(f"  ! Skipped (>{max_bytes} B): {file_path}")
            return keys

        with open(file_path, "rb") as fh:
            try:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    matches = BASE58_REGEX.findall(mm)
            except ValueError:  # empty file
                matches = ()

            if matches:
                if not quiet:
                    print(f"  + {len(matches)} key(s) in {file_path}")
                # decode bytes→str, Base58 is ASCII
                keys.update(m.decode("ascii") for m in matches)
    except (PermissionError, FileNotFoundError) as err:
        if not quiet:
            print(f"  ! Skipping {file_path}: {err}")
    except Exception as err:  # pragma: no cover
        if not quiet:
            print(f"  ! Error reading {file_path}: {err}")

    return keys


def scan_directory_for_private_keys(
    start_path: Path,
    *,
    quiet: bool,
    workers: int,
    max_size_mb: float | None,
) -> List[str]:
    """
    Recursively scan *start_path* for Base58‑formatted strings using a thread
    pool and mmap for performance. Returns a sorted list of unique keys.
    """
    max_bytes = int(max_size_mb * 1024 * 1024) if max_size_mb else None
    found: Set[str] = set()

    if not quiet:
        print(f"Scanning directory: {start_path} with {workers} worker(s)")

    # Generate all files first (cheap scandir)
    all_files: List[Path] = []
    stack: List[Path] = [start_path]

    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        all_files.append(path)
        except PermissionError as err:
            if not quiet:
                print(f"! Cannot access {current}: {err}")

    # Parallel file scanning
    with ThreadPoolExecutor(max_workers=workers) as exec_pool:
        future_to_path = {
            exec_pool.submit(
                _scan_file, p, quiet=quiet, max_bytes=max_bytes
            ): p
            for p in all_files
        }

        for fut in as_completed(future_to_path):
            found.update(fut.result())

    return sorted(found)


def convert_base58_to_wif(base58_key: str) -> str:
    """Return a simple WIF representation for *base58_key* (naïve prefix)."""
    prefix = "80" if len(base58_key) == 52 else "00"
    return f"{prefix}{base58_key}"


# ─────────────────────────── CLI ────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recursively scan a directory tree for Base58 private keys."
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default = current working directory).",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress output.",
    )
    p.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write raw keys to FILE (one per line).",
    )
    p.add_argument(
        "--show-wif",
        action="store_true",
        help="Also print WIF conversions for each key.",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Number of worker threads (default = {DEFAULT_WORKERS}).",
    )
    p.add_argument(
        "--max-size",
        type=float,
        metavar="MB",
        help="Skip files larger than MB megabytes (e.g. 10.5).",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    start_dir = Path(args.path).expanduser()

    if not validate_path(start_dir):
        print(f"Error: '{start_dir}' is not a valid directory.")
        sys.exit(1)

    keys = scan_directory_for_private_keys(
        start_dir,
        quiet=args.quiet,
        workers=max(1, args.workers),
        max_size_mb=args.max_size,
    )

    if keys:
        print(f"\nTotal keys found: {len(keys)}")
        for key in keys:
            print(f"Key: {key}")
            if args.show_wif:
                print(f"  WIF: {convert_base58_to_wif(key)}")

        if args.output:
            try:
                Path(args.output).write_text("\n".join(keys), encoding="utf-8")
                print(f"\nKeys saved to: {args.output}")
            except Exception as err:
                print(f"Unable to write to '{args.output}': {err}")
    else:
        print("No private keys found.")


if __name__ == "__main__":
    main()

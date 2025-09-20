#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional, cast

# ---------- helpers ----------


def iter_files(root: Path, follow_symlinks: bool) -> list[Path]:
    stack: list[Path] = [root]
    out: list[Path] = []
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink() and not follow_symlinks:
                            continue
                        if e.is_dir(follow_symlinks=follow_symlinks):
                            stack.append(Path(e.path))
                        elif e.is_file(follow_symlinks=follow_symlinks):
                            out.append(Path(e.path))
                    except OSError:
                        # skip entries we can't stat
                        pass
        except OSError:
            # skip dirs we can't enter
            pass
    return out


def hash_file(path: Path, algo: str, bytes_limit: Optional[int] = None) -> str:
    """Return hex digest of a file. If bytes_limit is set, hash only that many bytes."""
    h = hashlib.new(algo)
    bs: int = 1024 * 1024  # 1 MiB
    try:
        with open(path, "rb") as f:
            if bytes_limit is None:
                for chunk in iter(lambda: f.read(bs), b""):
                    h.update(chunk)
            else:
                remaining: int = bytes_limit
                while remaining > 0:
                    chunk = f.read(min(bs, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        return ""  # unreadable; treat as no-hash
    return h.hexdigest()


def fmt_size(n: int) -> str:
    """Human-readable (binary) size string."""
    size = float(n)
    for unit in ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]:
        if size < 1024 or unit == "PiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{n} B"


def fmt_time(ts: float) -> str:
    """Local timestamp formatted as YYYY-mm-dd HH:MM:SS."""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "?"


def str_key_for_order(path: Path, mode: str) -> tuple[str, str]:
    """
    Sorting key that always returns (primary:str, secondary:str) so types are uniform.
    mode: 'name' (alphabetical), 'mtime' (oldest first), 'size' (smallest first)
    """
    try:
        st = path.stat()
        if mode == "mtime":
            primary = f"{st.st_mtime:020.6f}"  # zero-padded numeric-as-string
        elif mode == "size":
            primary = f"{st.st_size:020d}"
        else:  # name
            primary = path.name.lower()
        return (primary, str(path))
    except OSError:
        return ("~", str(path))  # push unreadable to end deterministically


# ---------- argparse types ----------


class Args(argparse.Namespace):
    path: str
    algo: str
    partial_kb: int
    min_size: int
    follow_symlinks: bool
    order: str
    json: bool
    delete: Optional[int]


# ---------- main ----------


def main() -> None:
    p = argparse.ArgumentParser(description="Find duplicate files by content.")
    _ = p.add_argument("-p", "--path", required=True, help="Folder to scan")
    _ = p.add_argument(
        "-a",
        "--algo",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    _ = p.add_argument(
        "-k",
        "--partial-kb",
        type=int,
        default=256,
        help="Bytes (KB) to sample before full hash (use 0 to skip; default: 256)",
    )
    _ = p.add_argument(
        "-m",
        "--min-size",
        type=int,
        default=1,
        help="Ignore files smaller than this many bytes (default: 1)",
    )
    _ = p.add_argument(
        "-s",
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks (off by default)",
    )
    _ = p.add_argument(
        "-o",
        "--order",
        choices=["name", "mtime", "size"],
        default="name",
        help="Order inside each duplicate group (affects listing and --delete index)",
    )
    _ = p.add_argument(
        "-j", "--json", action="store_true", help="Output JSON (includes metadata)"
    )
    # --delete now means: delete the Nth file in each duplicate group (according to --order)
    _ = p.add_argument(
        "-d",
        "--delete",
        type=int,
        help="Delete the Nth file in each duplicate group (1=first, 2=second, ...). "
        "If a group has fewer than N files, it is skipped.",
    )
    args = cast(Args, p.parse_args())

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(2)

    # Collect files
    files: list[Path] = []
    for pth in iter_files(root, args.follow_symlinks):
        try:
            if pth.is_file() and pth.stat().st_size >= args.min_size:
                files.append(pth)
        except OSError:
            pass

    # Stage 1: group by size
    by_size: defaultdict[int, list[Path]] = defaultdict(list)
    for f in files:
        try:
            by_size[f.stat().st_size].append(f)
        except OSError:
            pass

    # Stage 2: partial hash within same-size groups
    sample_bytes: int = int(args.partial_kb) * 1024 if args.partial_kb > 0 else 0
    candidates: defaultdict[tuple[int, str], list[Path]] = defaultdict(list)

    def partial_job(fp: Path, _size: int) -> tuple[str, Path]:
        if sample_bytes <= 0:
            return (hash_file(fp, args.algo, None), fp)
        return (hash_file(fp, args.algo, sample_bytes), fp)

    with ThreadPoolExecutor(max_workers=max((os.cpu_count() or 4) * 2, 4)) as pool:
        futures: list[Future[tuple[str, Path]]] = []
        for size_val, group in by_size.items():
            if len(group) < 2:
                continue
            for fp in group:
                futures.append(pool.submit(partial_job, fp, size_val))

        for fut in as_completed(futures):
            try:
                h, fp = fut.result()
            except Exception:
                continue
            if not h:
                continue
            try:
                size_now = fp.stat().st_size
                candidates[(size_now, h)].append(fp)
            except OSError:
                pass

    # Stage 3: full hash confirmation per candidate bucket
    dup_groups: defaultdict[str, list[Path]] = defaultdict(list)
    with ThreadPoolExecutor(max_workers=max((os.cpu_count() or 4) * 2, 4)) as pool:
        futures_map: dict[Future[str], Path] = {}
        for (_size_key, _phash), group in candidates.items():
            if len(group) < 2:
                continue
            for fp in group:
                fut = pool.submit(hash_file, fp, args.algo, None)
                futures_map[fut] = fp

        for fut in as_completed(list(futures_map.keys())):
            fp = futures_map[fut]
            try:
                h = fut.result()
            except Exception:
                continue
            if h:
                dup_groups[h].append(fp)

    # Only keep groups with 2+ files
    filtered_groups: dict[str, list[Path]] = {
        h: v for h, v in dup_groups.items() if len(v) >= 2
    }

    # ----- ordering -----
    def ordered_group(paths: list[Path]) -> list[Path]:
        return sorted(paths, key=lambda pth: str_key_for_order(pth, args.order))

    # ----- Output -----
    if args.json:
        out: list[dict[str, object]] = []
        for h, ps in filtered_groups.items():
            items: list[dict[str, object]] = []
            for pth in ordered_group(ps):
                try:
                    st = pth.stat()
                    items.append(
                        {
                            "path": str(pth),
                            "name": pth.name,
                            "size": int(st.st_size),
                            "mtime": float(st.st_mtime),
                        }
                    )
                except OSError:
                    items.append(
                        {
                            "path": str(pth),
                            "name": pth.name,
                            "size": None,
                            "mtime": None,
                        }
                    )
            out.append({"hash": h, "algo": args.algo, "files": items})
        out.sort(
            key=lambda g: (-len(cast(list[object], g["files"])), cast(str, g["hash"]))
        )
        print(json.dumps(out, indent=2))
    else:
        if not filtered_groups:
            print("No duplicates found.")
        else:
            total_dupes = sum(len(v) - 1 for v in filtered_groups.values())
            print(
                f"Found {total_dupes} duplicate(s) across {len(filtered_groups)} group(s). (order: {args.order})\n"
            )
            for h, ps in sorted(
                filtered_groups.items(), key=lambda kv: (-len(kv[1]), kv[0])
            ):
                print(f"== {args.algo.upper()} {h} ({len(ps)} files) ==")
                ord_ps = ordered_group(ps)
                for idx, pth in enumerate(ord_ps, start=1):
                    try:
                        st = pth.stat()
                        print(
                            f"[{idx}] name={pth.name}  size={fmt_size(int(st.st_size))} mtime={fmt_time(float(st.st_mtime))}\n    {pth}"
                        )
                    except OSError:
                        print(f"[{idx}] name={pth.name}  size=?  mtime=?\n    {pth}")
                print()

    # ----- Deletion: delete the Nth file in each group -----
    if args.delete is not None and filtered_groups:
        delete_index: int = int(args.delete)  # 1-based
        if delete_index < 1:
            print(
                f"warning: --delete expects a positive index (1, 2, ...); got {args.delete}",
                file=sys.stderr,
            )
            sys.exit(2)

        deleted = 0
        for _h, paths in filtered_groups.items():
            ord_ps = ordered_group(paths)
            if delete_index <= len(ord_ps):
                target = ord_ps[delete_index - 1]
                try:
                    os.remove(target)
                    deleted += 1
                    print(f"Deleted [{delete_index}] {target}")
                except OSError as e:
                    print(f"warning: could not delete {target}: {e}", file=sys.stderr)
            else:
                print(f"warning: group size {len(ord_ps)} < {delete_index}; skipped")
        print(f"Deleted {deleted} file(s).")


if __name__ == "__main__":
    main()

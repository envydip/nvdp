#!/usr/bin/env python3
import argparse, hashlib, json, os, sys
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict


def iter_files(root: Path, follow_symlinks: bool) -> list[Path]:
    stack = [root]
    out = []
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    if e.is_symlink() and not follow_symlinks:
                        continue
                    if e.is_dir(follow_symlinks=follow_symlinks):
                        stack.append(Path(e.path))
                    elif e.is_file(follow_symlinks=follow_symlinks):
                        out.append(Path(e.path))
        except OSError:
            pass
    return out


def hash_file(path: Path, algo: str, bytes_limit: Optional[int] = None) -> str:
    h = hashlib.new(algo)
    bs = 1024 * 1024
    try:
        with open(path, "rb") as f:
            if bytes_limit is None:
                for chunk in iter(lambda: f.read(bs), b""):
                    h.update(chunk)
            else:
                remaining = bytes_limit
                while remaining > 0:
                    chunk = f.read(min(bs, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
    except (PermissionError, FileNotFoundError, OSError):
        return ""
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description="Find duplicate files by content.")
    p.add_argument("-p", "--path", required=True, help="Folder to scan")
    p.add_argument(
        "-a",
        "--algo",
        choices=["md5", "sha1", "sha256"],
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    p.add_argument(
        "--partial-kb",
        type=int,
        default=256,
        help="Bytes (KB) to sample before full hash (default: 256)",
    )
    p.add_argument(
        "--min-size",
        type=int,
        default=1,
        help="Ignore files smaller than this many bytes (default: 1)",
    )
    p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks (off by default)",
    )
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument(
        "--delete",
        action="store_true",
        help="DELETE duplicates (keep the first in each group). Use with care.",
    )
    args = p.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(2)

    files = [
        p
        for p in iter_files(root, args.follow_symlinks)
        if p.is_file() and p.stat().st_size >= args.min_size
    ]

    # stage 1: group by size
    by_size = defaultdict(list)
    for f in files:
        try:
            by_size[f.stat().st_size].append(f)
        except OSError:
            pass

    sample_bytes = args.partial_kb * 1024 if args.partial_kb > 0 else 0
    candidates: dict[str, list[Path]] = defaultdict(list)

    def partial_job(fp: Path, size: int):
        if sample_bytes <= 0:
            return (hash_file(fp, args.algo, None), fp)
        return (hash_file(fp, args.algo, sample_bytes), fp)

    with ThreadPoolExecutor(max_workers=(os.cpu_count() or 4) * 2) as pool:
        futures = []
        for size, group in by_size.items():
            if len(group) < 2:
                continue
            for fp in group:
                futures.append(pool.submit(partial_job, fp, size))

        for fut in as_completed(futures):
            h, fp = fut.result()
            if h:
                candidates[(fp.stat().st_size, h)].append(fp)

    dup_groups: dict[str, list[Path]] = defaultdict(list)
    with ThreadPoolExecutor(max_workers=(os.cpu_count() or 4) * 2) as pool:
        futures = {}
        for (_size, phash), group in candidates.items():
            if len(group) < 2:
                continue
            for fp in group:
                fut = pool.submit(hash_file, fp, args.algo, None)
                futures[fut] = fp

        for fut in as_completed(futures):
            fp = futures[fut]
            h = fut.result()
            if h:
                dup_groups[h].append(fp)

    dup_groups = {h: sorted(v) for h, v in dup_groups.items() if len(v) >= 2}

    if args.json:
        out = [
            {"hash": h, "algo": args.algo, "files": [str(p) for p in ps]}
            for h, ps in sorted(
                dup_groups.items(), key=lambda kv: (len(kv[1]), kv[0]), reverse=True
            )
        ]
        print(json.dumps(out, indent=2))
    else:
        if not dup_groups:
            print("No duplicates found.")
        else:
            print(
                f"Found {sum(len(v)-1 for v in dup_groups.values())} duplicate(s) across {len(dup_groups)} group(s):\n"
            )
            for h, ps in sorted(
                dup_groups.items(), key=lambda kv: (-len(kv[1]), kv[0])
            ):
                print(f"== {args.algo.upper()} {h} ({len(ps)} files) ==")
                for pth in ps:
                    print(pth)
                print()

    if args.delete and dup_groups:
        deleted = 0
        for _h, paths in dup_groups.items():
            for fp in paths[1:]:
                try:
                    os.remove(fp)
                    deleted += 1
                except OSError as e:
                    print(f"warning: could not delete {fp}: {e}", file=sys.stderr)
        print(f"Deleted {deleted} duplicate files.")


if __name__ == "__main__":
    main()

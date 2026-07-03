#!/usr/bin/env python3
"""
ioc_tool.py - Manual IOC collector + hunter (Redline/IOC-Editor replacement)

Usage:
    Collect IOCs from sample file(s):
        python3 ioc_tool.py collect sample1.exe

    Hunt a target directory using collected IOCs:
        python3 ioc_tool.py hunt TARGETDIRECTORY

Workflow:
    1. Run 'collect' on each malware sample. It hashes (MD5/SHA1), gets size,
       pulls printable strings, and asks if you want to add more samples.
       Saves everything to iocs.json.
    2. Run 'hunt' against TARGETDIRECTORY. It walks every file, hashes it,
       checks size, checks filename fragments, checks strings — and prints
       a report: total entries + which file matched which IOC.

No malware is ever executed. Pure static analysis (hash/size/strings).
"""

import argparse
import hashlib
import json
import os
import re
import sys

IOC_DB = "iocs.json"


def md5_sha1(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
    return md5.hexdigest(), sha1.hexdigest()


def get_strings(path, min_len=6, limit=25):
    """Crude equivalent of `strings` command, no external tool needed."""
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    with open(path, "rb") as f:
        data = f.read()
    found = pattern.findall(data)
    # Dedup, keep order, limit count so output stays readable
    seen = []
    for s in found:
        val = s.decode(errors="ignore")
        if val not in seen:
            seen.append(val)
        if len(seen) >= limit:
            break
    return seen


def load_db():
    if os.path.exists(IOC_DB):
        with open(IOC_DB) as f:
            return json.load(f)
    return {"samples": []}


def save_db(db):
    with open(IOC_DB, "w") as f:
        json.dump(db, f, indent=2)


def collect(args):
    db = load_db()
    paths = args.paths

    while True:
        for path in paths:
            if not os.path.isfile(path):
                print(f"[!] Skip, not a file: {path}")
                continue

            md5, sha1 = md5_sha1(path)
            size = os.path.getsize(path)
            strings = get_strings(path)
            filename = os.path.basename(path)

            print(f"\n=== {filename} ===")
            print(f"MD5:   {md5}")
            print(f"SHA1:  {sha1}")
            print(f"Size:  {size} bytes")
            print(f"Strings found: {len(strings)} (showing up to 25)")
            for s in strings[:10]:
                print(f"    {s}")
            if len(strings) > 10:
                print(f"    ... {len(strings)-10} more (saved to iocs.json)")

            confirm = input(f"\nConfirm size {size} bytes matches file explorer? [Y/n]: ").strip().lower()
            if confirm == "n":
                real_size = input("Enter correct size in bytes: ").strip()
                if real_size.isdigit():
                    size = int(real_size)

            db["samples"].append({
                "filename": filename,
                "path": os.path.abspath(path),
                "md5": md5,
                "sha1": sha1,
                "size": size,
                "strings": strings,
            })

        save_db(db)
        print(f"\n[+] Saved to {IOC_DB}. Total samples collected: {len(db['samples'])}")

        more = input("\nAdd another sample file? (enter path, or blank to stop): ").strip()
        if not more:
            break
        paths = [more]


def add_strings(args):
    """Manually add analyst-provided string IOCs (e.g. from a Threat Intel note)
    that may not surface via automatic string extraction."""
    db = load_db()
    db["samples"].append({
        "filename": "manual_TI_strings",
        "path": "",
        "md5": "",
        "sha1": "",
        "size": 0,
        "strings": args.strings,
    })
    save_db(db)
    print(f"[+] Added {len(args.strings)} manual string IOC(s):")
    for s in args.strings:
        print(f"    {s}")


def hunt(args):
    db = load_db()
    if not db["samples"]:
        print("[!] No IOCs collected yet. Run 'collect' first.")
        sys.exit(1)

    target = args.target
    if not os.path.isdir(target):
        print(f"[!] Not a directory: {target}")
        sys.exit(1)

    md5_map = {s["md5"]: s for s in db["samples"]}
    sha1_map = {s["sha1"]: s for s in db["samples"]}
    size_map = {s["size"]: s for s in db["samples"]}
    name_fragments = {s["filename"].lower(): s for s in db["samples"]}
    all_strings = set()
    for s in db["samples"]:
        all_strings.update(s["strings"])

    matches = []

    print(f"[*] Scanning {target} ...")
    for root, _, files in os.walk(target):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                md5, sha1 = md5_sha1(fpath)
            except (OSError, PermissionError):
                continue

            hit_reasons = []
            if md5 in md5_map:
                hit_reasons.append(f"MD5 match ({md5})")
            if sha1 in sha1_map:
                hit_reasons.append(f"SHA1 match ({sha1})")
            if size in size_map:
                hit_reasons.append(f"Size match ({size} bytes)")
            if fname.lower() in name_fragments:
                hit_reasons.append("Filename match")
            else:
                for frag in name_fragments:
                    if frag in fname.lower():
                        hit_reasons.append(f"Filename contains '{frag}'")
                        break

            # string match (only if small-ish text-based file, skip huge binaries for speed)
            if size < 5_000_000:
                try:
                    file_strings = get_strings(fpath, limit=500)
                    file_blob = "\n".join(file_strings)
                    found_strs = [ioc_str for ioc_str in all_strings if ioc_str and ioc_str in file_blob]
                    if found_strs:
                        hit_reasons.append(f"String match: {found_strs[:3]}")
                except (OSError, PermissionError):
                    pass

            if hit_reasons:
                matches.append({"path": fpath, "reasons": hit_reasons})

    print(f"\n=== IOC REPORT ===")
    print(f"Total entries (matched files): {len(matches)}\n")
    for m in matches:
        print(f"File: {m['path']}")
        for r in m["reasons"]:
            print(f"    - {r}")
        print()

    with open("ioc_report.json", "w") as f:
        json.dump(matches, f, indent=2)
    print(f"[+] Full report saved to ioc_report.json")


def main():
    parser = argparse.ArgumentParser(description="Manual IOC collector + hunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_collect = sub.add_parser("collect", help="Extract IOCs from sample file(s)")
    p_collect.add_argument("paths", nargs="+", help="Path(s) to malware sample file(s)")
    p_collect.set_defaults(func=collect)

    p_hunt = sub.add_parser("hunt", help="Hunt a target directory using collected IOCs")
    p_hunt.add_argument("target", help="Path to target directory")
    p_hunt.set_defaults(func=hunt)

    p_strings = sub.add_parser("add-strings", help="Manually add analyst-provided string IOCs (e.g. from a TI note)")
    p_strings.add_argument("strings", nargs="+", help="One or more string IOCs to add")
    p_strings.set_defaults(func=add_strings)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

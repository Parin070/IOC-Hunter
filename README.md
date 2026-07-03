# IOC-Hunter

A Linux-native replacement for Mandiant Redline + IOC Editor.

Because installing a Windows VM just to click through a GUI wizard felt like a personal insult to my terminal.

## Why this exists

Working through Security Blue Team's Threat Hunting course, the capstone required:
- Extracting IOCs (MD5, SHA1, size, filename, strings) from two malware samples
- Building `.ioc` files in Mandiant IOC Editor
- Auditing a target directory with Mandiant Redline
- Reporting on IOC matches

Problem: both tools are Windows-only. The "official" path is spin up a Windows 10 dev VM, disable Defender, install two GUI apps, click through wizards, export a `.mans` file, parse a report.

That's four extra steps to do something `md5sum`, `stat`, and `grep -r` already do natively on any Linux box. Redline isn't running some proprietary black-box algorithm — it's hashing files and matching strings. So instead of babysitting a Windows VM for one assignment, I wrote a CLI that does the same job in native Python, on Kali, with zero GUI and zero extra OS.

Also: real malware samples were involved. Less surface area to accidentally detonate something is generally a good policy. Static analysis only, nothing here executes a sample — ever.

## What it does

Two commands, same job Redline does:

**`collect`** — point it at a malware sample, it extracts:
- MD5 hash
- SHA1 hash
- File size (with a manual override prompt if it doesn't match what you see in a file browser)
- Printable strings (crude but effective `strings`-equivalent, no external binary needed)

Then asks if you want to add another sample. Keep feeding it until done.

**`add-strings`** — for IOCs that come from a threat intel note rather than the binary itself (a known C2 string, a campaign tag, whatever). Bolts them onto the same IOC database without touching JSON by hand.

**`hunt`** — point it at a target directory (or a scoped subdirectory, e.g. one user's home folder). It walks every file, hashes it, checks size, checks filename, checks for string overlap, and prints a report: total matched entries + which file tripped which IOC.

## Usage

```bash
# extract IOCs from your malware samples
python3 ioc_tool.py collect sample1.exe sample2.exe

# add any extra IOCs a threat intel note gave you
python3 ioc_tool.py add-strings "some-c2-string" "#CAMPAIGNTAG"

# hunt a target directory (scope it down if you can — don't scan the whole disk for fun)
python3 ioc_tool.py hunt /path/to/target/DaveS
```

Output:
- Console report — total entries + per-file match reasons
- `ioc_report.json` — same data, saved locally for write-ups (not committed to this repo)

## How it works

No dependencies outside the Python standard library — `hashlib`, `os`, `re`, `json`, `argparse`. Runs on any Linux box with Python 3, no pip install, no internet required after you've got the files locally.

String extraction is a regex over printable ASCII byte runs (`[ -~]{6,}`), same idea as the `strings` command, just inline so there's no dependency on it being installed.

String matching on hunt uses substring containment, not exact-token matching — a lot of IOC strings show up embedded inside longer binary strings, and exact matching misses those.

## Note on real capstone data

No malware samples, hashes, or target-directory contents from the actual SBT challenge are included in this repo. This is the tool, not the answer key.

## Why not just... use Redline

Because "install Windows, disable your antivirus, click six menus deep to tick a checkbox that toggles SHA1 collection because the docs say it randomly stops working" is not a debugging experience I signed up for. `find` and `hashlib` don't have mood swings.

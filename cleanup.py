#!/usr/bin/env python3
"""Remove this repo's compiled GhidraScript bundles from Ghidra's cache.

Ghidra 9.2 replaced the old per-script ``bin`` directory (the one the
original ``cleanup`` script and ``ghidra_bin_location.txt`` chased) with an
OSGi bundle cache, so the loose ``.class`` files no longer exist. The cache
now lives under the user settings directory:

    <settings>/osgi/compiled-bundles/<hash>/

where ``<hash>`` identifies one script source directory. Ghidra recompiles a
Java script bundle automatically when its sources change, so clearing the
cache is normally unnecessary - reach for this only when you suspect a stale
or half-written bundle. Python scripts (Jython or PyGhidra) are never
compiled, so there is nothing to clean for them.

Where ``<settings>`` is (Ghidra 11.1+):

    Linux:    ~/.config/ghidra/ghidra_<version>_PUBLIC
    macOS:    ~/Library/ghidra/ghidra_<version>_PUBLIC
    Windows:  %APPDATA%\\ghidra\\ghidra_<version>_PUBLIC

Ghidra 9.2 - 11.0 used ~/.ghidra/.ghidra_<version>_PUBLIC instead; both
layouts are probed.

Usage:
    python3 cleanup.py                 # remove bundles built from this checkout
    python3 cleanup.py --dry-run       # show what would be removed
    python3 cleanup.py --all           # remove every compiled bundle
    python3 cleanup.py --felix         # also clear the Felix bundle cache
    python3 cleanup.py --settings-dir <path>
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent


# Ghidra <=11.0 puts settings in ~/.ghidra; 11.1+ moved to platform config dirs.
# Probe all of them rather than deriving a version-specific path.
def candidate_roots():
    roots = []
    env = os.environ.get("GHIDRA_USER_SETTINGS")
    if env:
        roots.append(Path(env))
    home = Path.home()
    roots += [home / ".ghidra", home / ".config" / "ghidra", home / "Library" / "ghidra"]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        roots.append(Path(xdg) / "ghidra")
    for var in ("APPDATA", "LOCALAPPDATA"):
        val = os.environ.get(var)
        if val:
            roots.append(Path(val) / "ghidra")
    return roots


def find_bundle_dirs(explicit=None):
    """Locate every <settings>/osgi/compiled-bundles directory."""
    if explicit:
        root = Path(explicit).expanduser()
        if not root.is_dir():
            sys.exit("no such settings directory: %s" % root)
        roots = [root]
    else:
        roots = [r for r in candidate_roots() if r.is_dir()]

    found = []
    for root in roots:
        # The settings dir may be the root itself or a ghidra_<version> child.
        for base in [root] + sorted(p for p in root.iterdir() if p.is_dir()):
            cb = base / "osgi" / "compiled-bundles"
            if cb.is_dir() and cb not in found:
                found.append(cb)
    return found


def repo_class_names():
    """Java script names anywhere in this checkout, e.g. {'MyScript'}."""
    return {p.stem for p in REPO.rglob("*.java") if ".git" not in p.parts}


def owns_bundle(bundle, names):
    return any((bundle / (n + ".class")).exists() for n in names)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true",
                    help="remove every compiled bundle, not just this checkout's")
    ap.add_argument("--felix", action="store_true",
                    help="also clear the Felix bundle cache alongside compiled-bundles")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="list what would be removed without deleting")
    ap.add_argument("--settings-dir",
                    help="explicit Ghidra user settings directory")
    args = ap.parse_args()

    bundle_dirs = find_bundle_dirs(args.settings_dir)
    if not bundle_dirs:
        print("No Ghidra bundle cache found. Looked under:")
        if args.settings_dir:
            print("  %s" % Path(args.settings_dir).expanduser())
            print("\nExpected an osgi/compiled-bundles directory there or in a "
                  "version subdirectory.")
        else:
            for r in candidate_roots():
                print("  %s%s" % (r, "" if r.is_dir() else "  (missing)"))
            print("\nPass --settings-dir if Ghidra keeps its settings elsewhere.")
        return 1

    names = repo_class_names()
    if not names and not args.all:
        sys.exit("no .java files under %s; use --all to clear everything" % REPO)

    removed = 0
    for cache in bundle_dirs:
        print("cache: %s" % cache)
        # Guard against a mistyped --settings-dir turning this into rm -rf.
        if cache.name != "compiled-bundles":
            print("  refusing to touch unexpected path")
            continue
        for bundle in sorted(p for p in cache.iterdir() if p.is_dir()):
            if not args.all and not owns_bundle(bundle, names):
                print("  skip   %s  (not built from this checkout)" % bundle.name)
                continue
            if args.dry_run:
                print("  would remove %s" % bundle.name)
            else:
                shutil.rmtree(bundle)
                print("  removed %s" % bundle.name)
            removed += 1

        if args.felix:
            felix = cache.parent / "felixcache"
            if felix.is_dir():
                if args.dry_run:
                    print("  would remove felixcache")
                else:
                    shutil.rmtree(felix)
                    print("  removed felixcache")

    if removed == 0:
        print("\nNothing to remove.")
    elif args.dry_run:
        print("\n%d bundle(s) would be removed." % removed)
    else:
        print("\n%d bundle(s) removed; Ghidra will rebuild on next run." % removed)
    return 0


if __name__ == "__main__":
    sys.exit(main())

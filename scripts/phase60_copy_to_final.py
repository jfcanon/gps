"""Phase 60 Step 1 — Copy 2 BR domain v2 CSVs → data/outputs/br/{slug}.final.csv

Source: data/outputs/{slug}_rechecked_controls_v2.csv
Dest:   data/outputs/br/{slug}.final.csv

Does NOT modify content — pure copy. URL backfill done in subsequent steps.
Mirror of scripts/phase59_copy_to_final.py.
"""
import csv
import pathlib
import shutil

SLUGS = ["backup", "siterecovery"]

SRC_DIR = pathlib.Path("data/outputs")
DEST_DIR = pathlib.Path("data/outputs/br")


def copy_slug(slug: str) -> tuple[bool, int]:
    src = SRC_DIR / f"{slug}_rechecked_controls_v2.csv"
    dest = DEST_DIR / f"{slug}.final.csv"

    if not src.exists():
        print(f"  {slug:<16} SKIP — source not found: {src}")
        return False, 0

    if dest.exists():
        print(f"  {slug:<16} SKIP — dest already exists: {dest}")
        return False, 0

    shutil.copy2(src, dest)
    rows = list(csv.DictReader(open(dest)))
    print(f"  {slug:<16} OK    rows={len(rows):>3}")
    return True, len(rows)


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 60 Step 1 — Copy BR v2 CSVs to br/")
    print("=" * 60)
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    total_copied = 0
    total_rows = 0
    for slug in SLUGS:
        ok, n = copy_slug(slug)
        if ok:
            total_copied += 1
            total_rows += n

    print()
    print(f"Copied: {total_copied}/{len(SLUGS)} files  |  Total rows: {total_rows}")
    print("Done.")

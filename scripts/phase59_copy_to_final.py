"""Phase 59 Step 1 — Copy 9 IM domain v2 CSVs → data/outputs/im/{slug}.final.csv

Source: data/outputs/{slug}_rechecked_controls_v2.csv
Dest:   data/outputs/im/{slug}.final.csv

Does NOT modify content — pure copy. URL backfill done in subsequent steps.
Mirror of scripts/phase57_copy_to_final.py.
"""
import csv
import pathlib
import shutil

SLUGS = [
    "addds", "apimanagement", "attestation", "botservice", "cloudshell",
    "intelligentrecommendations", "spatialanchors", "trustedhardwareim",
    "universalprint",
]

SRC_DIR = pathlib.Path("data/outputs")
DEST_DIR = pathlib.Path("data/outputs/im")


def copy_slug(slug: str) -> tuple[bool, int]:
    src = SRC_DIR / f"{slug}_rechecked_controls_v2.csv"
    dest = DEST_DIR / f"{slug}.final.csv"

    if not src.exists():
        print(f"  {slug:<28} SKIP — source not found: {src}")
        return False, 0

    if dest.exists():
        print(f"  {slug:<28} SKIP — dest already exists: {dest}")
        return False, 0

    shutil.copy2(src, dest)
    rows = list(csv.DictReader(open(dest)))
    print(f"  {slug:<28} OK    rows={len(rows):>3}")
    return True, len(rows)


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 59 Step 1 — Copy IM v2 CSVs to im/")
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

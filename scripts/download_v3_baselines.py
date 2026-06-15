"""
download_v3_baselines.py
------------------------
Phase 34: Download 118 per-service MCSB v3 xlsx files from GitHub and parse
the "Feature Summary" sheet from each into a single merged CSV.

Source:
  https://github.com/MicrosoftDocs/SecurityBenchmarks/tree/master/
  Azure%20Offer%20Security%20Baselines/3.0

Output:
  data/outputs/v3_service_controls_raw.csv  (~4,500 rows)

Columns:
  service_name, control_domain, asb_control_id, asb_control_title,
  guidance, responsibility, feature_name, feature_description,
  feature_supported, feature_enabled_by_default,
  feature_reference, feature_notes, guidance_notes

Usage:
  python3 download_v3_baselines.py [--out PATH] [--cache-dir DIR] [--no-cache]

Cache behaviour:
  xlsx files are cached in data/inputs/v3_baselines/ and reused on re-run.
  Use --no-cache to force re-download.
"""

import csv
import time
import argparse
import subprocess
import json
from pathlib import Path

import pandas as pd
import requests

ROOT      = Path(__file__).parent.parent
CACHE_DIR = ROOT / "data" / "inputs" / "v3_baselines"
OUT_DIR   = ROOT / "data" / "outputs"
OUT_FILE  = OUT_DIR / "v3_service_controls_raw.csv"

GITHUB_API = (
    "https://api.github.com/repos/MicrosoftDocs/SecurityBenchmarks"
    "/contents/Azure%20Offer%20Security%20Baselines/3.0"
)

# Known column name variants → canonical
COL_MAP = {
    "control domain":              "control_domain",
    "asb control id":              "asb_control_id",
    "asb control title":           "asb_control_title",
    "guidance":                    "guidance",
    "responsibility":              "responsibility",
    "feature name":                "feature_name",
    "feature description":         "feature_description",
    "feature supported":           "feature_supported",
    "feature enabled by default":  "feature_enabled_by_default",
    "feature reference":           "feature_reference",
    "feature notes":               "feature_notes",
    "guidance notes":              "guidance_notes",
}

CANONICAL_COLS = [
    "service_name", "control_domain", "asb_control_id", "asb_control_title",
    "guidance", "responsibility", "feature_name", "feature_description",
    "feature_supported", "feature_enabled_by_default",
    "feature_reference", "feature_notes", "guidance_notes",
]


def _gh_token() -> dict:
    """Return Authorization header if gh CLI is available."""
    try:
        tok = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
        return {"Authorization": f"token {tok}"}
    except Exception:
        return {}


def list_files() -> list[dict]:
    """Return list of {name, download_url} for all xlsx in the GitHub directory."""
    resp = requests.get(GITHUB_API, headers=_gh_token(), timeout=30)
    resp.raise_for_status()
    items = resp.json()
    return [
        {"name": i["name"], "download_url": i["download_url"]}
        for i in items
        if i["name"].endswith(".xlsx")
    ]


def service_name_from_filename(filename: str) -> str:
    """Extract short service name from xlsx filename."""
    return filename.replace("-azure-security-benchmark-v3-latest-security-baseline.xlsx", "")


def download_xlsx(url: str, dest: Path, headers: dict) -> bool:
    """Download xlsx to dest. Returns True on success."""
    try:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        return True
    except Exception as e:
        print(f"    [WARN] Download failed: {e}")
        return False


def parse_feature_summary(xlsx_path: Path, service_name: str) -> list[dict]:
    """Parse Feature Summary sheet. Returns list of row dicts."""
    try:
        xf = pd.read_excel(xlsx_path, sheet_name=None)
    except Exception as e:
        print(f"    [WARN] Cannot open {xlsx_path.name}: {e}")
        return []

    # Find Feature Summary sheet (name may vary slightly)
    sheet = None
    for name, df in xf.items():
        if "feature" in name.lower() and "summary" in name.lower():
            sheet = df
            break
    if sheet is None:
        print(f"    [WARN] No Feature Summary sheet in {xlsx_path.name}")
        return []

    # Normalize column names
    sheet = sheet.rename(columns={
        col: COL_MAP.get(col.strip().lower(), col.strip().lower())
        for col in sheet.columns
    })

    rows = []
    for _, row in sheet.iterrows():
        record = {"service_name": service_name}
        for canon in CANONICAL_COLS[1:]:  # skip service_name
            record[canon] = str(row.get(canon, "")).strip()
            if record[canon] in ("nan", "None"):
                record[canon] = ""
        # Skip rows with no ASB control ID
        if not record.get("asb_control_id"):
            continue
        rows.append(record)

    return rows


def main(out_path: str, cache_dir: Path, no_cache: bool) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    headers = _gh_token()

    print("Listing files from GitHub...")
    files = list_files()
    print(f"  Found {len(files)} xlsx files")

    all_rows: list[dict] = []
    failed = 0

    for i, f in enumerate(files, 1):
        service = service_name_from_filename(f["name"])
        local   = cache_dir / f["name"]

        if no_cache or not local.exists():
            print(f"  [{i:3d}/{len(files)}] Downloading {service}...")
            ok = download_xlsx(f["download_url"], local, headers)
            if not ok:
                failed += 1
                continue
            time.sleep(0.1)   # gentle rate limit
        else:
            print(f"  [{i:3d}/{len(files)}] Cached     {service}")

        rows = parse_feature_summary(local, service)
        all_rows.extend(rows)

    out = Path(out_path)
    with open(out, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=CANONICAL_COLS)
        writer.writeheader()
        writer.writerows(all_rows)

    services = len({r["service_name"] for r in all_rows})
    print(f"\nTotal: {len(all_rows)} rows from {services} services → {out}")
    if failed:
        print(f"  [WARN] {failed} files failed to download")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download + parse 118 v3 per-service xlsx files")
    parser.add_argument("--out",       default=str(OUT_FILE),  help="Output CSV path")
    parser.add_argument("--cache-dir", default=str(CACHE_DIR), help="Local xlsx cache directory")
    parser.add_argument("--no-cache",  action="store_true",    help="Force re-download even if cached")
    args = parser.parse_args()
    main(args.out, Path(args.cache_dir), args.no_cache)

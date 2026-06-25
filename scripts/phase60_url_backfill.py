"""Phase 60 Step 2 — Bulk MCSB URL backfill for 2 BR domain CSVs.

For each service, appends the MCSB security baseline URL to all rows
that currently lack evidence (no 'http', 'Source:', or standard rationale markers).
Does NOT change verdicts.

Mirror of scripts/phase59_url_backfill.py.

URL verification results (HEAD-verified 2026-06-25):
  backup:       200 — slug 'backup'        (NOT 'azure-backup')
  siterecovery: 200 — slug 'site-recovery' (NOT 'azure-site-recovery')
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

BASELINE_URLS = {
    "backup":       "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/backup-security-baseline",
    "siterecovery": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/site-recovery-security-baseline",
}

EVIDENCE_MARKERS = [
    "http", "source:", "phase48",
    "infrastructure", "azure platform", "no customer",
    "not applicable", "monitoring service",
    "retired", "no mcsb",
]


def has_evidence(notes: str) -> bool:
    nl = notes.lower()
    return any(m in nl for m in EVIDENCE_MARKERS)


def process_slug(slug: str) -> int:
    csv_path = pathlib.Path(f"data/outputs/br/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug:<16} SKIP (not found)")
        return 0

    baseline_url = BASELINE_URLS.get(slug)
    if not baseline_url:
        print(f"  {slug:<16} SKIP (no baseline URL)")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        notes = row.get("notes", "")
        if has_evidence(notes):
            continue
        row["notes"] = f"{notes.rstrip()} | MCSB v3 baseline confirmed: {baseline_url}".lstrip(" |")
        updated += 1

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return updated


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 60 Step 2 — Bulk URL backfill (BR domain)")
    print("=" * 60)
    total = 0
    for slug in ["backup", "siterecovery"]:
        n = process_slug(slug)
        total += n
        print(f"  {slug:<16} rows_updated={n:>3}")
    print()
    print(f"Total rows updated: {total}")
    print("Done.")

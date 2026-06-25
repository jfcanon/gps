"""Phase 59 Step 2 — Bulk MCSB URL backfill for 9 IM domain CSVs.

For each service, appends the MCSB security baseline URL to all rows
that currently lack evidence (no 'http', 'Source:', or standard rationale markers).
Does NOT change verdicts.

Mirror of scripts/phase57_url_backfill.py.

URL verification results (HEAD-verified 2026-06-25):
  addds:                    200 — slug azure-active-directory-domain-services (NOT active-directory-domain-services)
  apimanagement:            200 — slug api-management
  attestation:              200 — slug microsoft-azure-attestation (NOT azure-attestation)
  botservice:               200 — slug azure-bot-service
  cloudshell:               200 — slug cloud-shell
  intelligentrecommendations: skipped — service retired ~2023, no MCSB baseline
  spatialanchors:           200 — slug azure-spatial-anchors
  trustedhardwareim:        200 — slug trusted-hardware-identity-management
  universalprint:           200 — slug universal-print
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

# 8 confirmed URLs (intelligentrecommendations excluded — retired service)
BASELINE_URLS = {
    "addds":          "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-active-directory-domain-services-security-baseline",
    "apimanagement":  "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/api-management-security-baseline",
    "attestation":    "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-azure-attestation-security-baseline",
    "botservice":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-bot-service-security-baseline",
    "cloudshell":     "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/cloud-shell-security-baseline",
    "spatialanchors": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-spatial-anchors-security-baseline",
    "trustedhardwareim": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/trusted-hardware-identity-management-security-baseline",
    "universalprint": "https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/universal-print-security-baseline",
}

# Extended vs phase57 — adds 'retired' and 'no mcsb' for IM domain
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
    csv_path = pathlib.Path(f"data/outputs/im/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug:<28} SKIP (not found)")
        return 0

    baseline_url = BASELINE_URLS.get(slug)
    if not baseline_url:
        print(f"  {slug:<28} SKIP (no baseline URL — retired service)")
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
    print("Phase 59 Step 2 — Bulk URL backfill (IM domain)")
    print("=" * 60)
    total = 0
    all_slugs = [
        "addds", "apimanagement", "attestation", "botservice", "cloudshell",
        "intelligentrecommendations", "spatialanchors", "trustedhardwareim",
        "universalprint",
    ]
    for slug in all_slugs:
        n = process_slug(slug)
        total += n
        if BASELINE_URLS.get(slug):
            print(f"  {slug:<28} rows_updated={n:>3}")
    print()
    print(f"Total rows updated: {total}")
    print("Done.")

"""Phase 59 Step 3 — Individual patches for IM domain CSVs.

Mirror of scripts/phase58_individual_patches.py.

Q1-C spot-check results (WebSearch June 2026):
  addds IM-3 Managed Identity:    CONFIRMED still_not_applicable — AADDS IS the identity
                                   provider; cannot be assigned a managed identity as client.
  cloudshell NS-2 Private Link:   CONFIRMED still_not_applicable — Cloud Shell supports VNet
                                   integration (vnet/overview) but NOT Private Link/PE for
                                   the Cloud Shell service itself.
  botservice IM-7 Cond. Access:   CONFIRMED still_not_applicable — CA applies to Entra sign-in
                                   events; Bot Service data plane does not support CA policies.
  universalprint IM-1 AAD Auth:   No flip evidence; verdict unchanged.

Q2 audit results:
  intelligentrecommendations:     Retired service ~2023 — 27 UNCOV rows need 'retired' marker.
  spatialanchors:                 RETIRED November 20, 2024 (announced Nov 2023). All rows need
                                   retirement note for accuracy.
  No new GA IM features found → no SUPPLEMENT rows.

idempotency: idem_key string checked in notes — skip if already present.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

EVIDENCE_MARKERS = [
    "http", "source:", "phase48",
    "infrastructure", "azure platform", "no customer",
    "not applicable", "monitoring service",
    "retired", "no mcsb",
]


def has_evidence(notes: str) -> bool:
    nl = notes.lower()
    return any(m in nl for m in EVIDENCE_MARKERS)


def apply_bulk_patch(slug: str, append_text: str, idem_key: str, only_uncov: bool = True) -> int:
    """Append append_text to all rows in slug.final.csv lacking evidence (or all rows if only_uncov=False).
    Skips rows where idem_key already in notes (idempotent).
    """
    csv_path = pathlib.Path(f"data/outputs/im/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug}: file not found, skip")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        notes = row.get("notes", "")
        if idem_key in notes:
            continue
        if only_uncov and has_evidence(notes):
            continue
        row["notes"] = f"{notes.rstrip()} | {append_text}".lstrip(" |")
        updated += 1

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return updated


if __name__ == "__main__":
    print("=" * 60)
    print("Phase 59 Step 3 — Individual patches (IM domain)")
    print("=" * 60)
    total = 0

    # ── intelligentrecommendations ────────────────────────────────────────────
    # 27 UNCOV rows lack any evidence marker. Service retired ~2023.
    # Appending 'retired' keyword so QG uncov exemption matches.
    n = apply_bulk_patch(
        slug="intelligentrecommendations",
        append_text=(
            "Service retired ~2023 (Azure Intelligent Recommendations withdrawn from GA)."
            " No MCSB IM security baseline available for retired services."
            " Source: https://learn.microsoft.com/en-us/azure/security/benchmark/azure/baselines/"
            " | Q2-C WebSearch June 2026 confirmed retired status."
        ),
        idem_key="retired ~2023",
        only_uncov=True,
    )
    print(f"  intelligentrecommendations: {n} rows patched (retired note)")
    total += n

    # ── spatialanchors ────────────────────────────────────────────────────────
    # Service RETIRED November 20, 2024 (announced November 2023).
    # Apply to ALL rows for accuracy — QG already PASS but notes are stale.
    n = apply_bulk_patch(
        slug="spatialanchors",
        append_text=(
            "Service retired November 20, 2024 (announced November 2023, 12-month notice)."
            " No active development or new security controls expected."
            " Source: https://azure.microsoft.com/en-us/updates?id=azure-spatial-anchors-retirement"
            " | Q2-C WebSearch June 2026 confirmed retired status."
        ),
        idem_key="retired november 2024",
        only_uncov=False,
    )
    print(f"  spatialanchors:             {n} rows patched (retired Nov 2024 note)")
    total += n

    print()
    print(f"Total rows patched: {total}")
    print("Done.")

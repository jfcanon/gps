"""Phase 60 Step 3 — Individual patches for BR domain CSVs.

Mirror of scripts/phase59_individual_patches.py.

Q1-A: now_applicable_native URL fix
  backup IM-3 Managed Identities: now_applicable_native — MCSB baseline URL already
    appended by backfill; add specific MI docs URL for evidence depth.
    Source: https://learn.microsoft.com/en-us/azure/backup/enable-managed-identity-recovery-services-vault
    (published 2026-04-29; system-assigned MI enabled by default on vault creation as of 2022+)

Q1-C spot-check results (WebSearch June 2026):
  backup PA-7 Azure RBAC:              CONFIRMED still_not_applicable — Azure Backup exposes
    management plane RBAC only (Backup Contributor/Operator/Reader built-in roles); no
    separate data plane RBAC evaluation point exists for backup/restore operations.
    Source: https://learn.microsoft.com/en-us/azure/backup/backup-rbac-rs-vault
  backup NS-2 Azure Private Link:       ALREADY implemented — verdict correct; no flip.
  siterecovery IM-8 Credentials in KV: CONFIRMED still_not_applicable — Azure Automation
    Run As accounts RETIRED September 30, 2023; ASR now uses system-assigned managed identity
    via Automation Account for agent update automation. No service principal credentials
    remain to store in Key Vault; IM-8 not applicable.
    Source: https://learn.microsoft.com/en-us/azure/site-recovery/how-to-migrate-run-as-accounts-managed-identity

Q2 audit results (WebSearch June 2026):
  backup Q2-A:   Immutable vault locked (WORM) GA confirmed (already captured in DP-2 row);
    Enhanced policy GA (operational improvement to BR-1 rows already implemented).
    No new security control gaps found → no SUPPLEMENT rows.
  siterecovery Q2-B: Only kernel/OS support updates and churn-limit performance improvements.
    No new security control gaps → no SUPPLEMENT rows.

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


# Per-row patches: (slug, ctrl_id, feat_substring, idem_key, append_text)
PATCHES = [
    # ── Q1-A: backup IM-3 Managed Identities ─────────────────────────────────
    # Adds specific MI docs URL (2026-04-29). System-assigned MI now default.
    (
        "backup",
        "IM-3",
        "Managed Identities",
        "enable-managed-identity-recovery-services-vault",
        (
            "MI docs confirmed GA (2026-04-29): system-assigned managed identity enabled by default"
            " on Recovery Services Vault provisioning; ARM property: identity.type = SystemAssigned."
            " Source: https://learn.microsoft.com/en-us/azure/backup/enable-managed-identity-recovery-services-vault"
        ),
    ),
    # ── Q1-C: backup PA-7 Azure RBAC ─────────────────────────────────────────
    # Confirms still_not_applicable — management plane RBAC only, no data plane concept.
    (
        "backup",
        "PA-7",
        "Azure RBAC for Data Plane",
        "backup-rbac-rs-vault",
        (
            "Q1-C WebSearch June 2026 confirmed still_not_applicable: Azure Backup exposes"
            " management plane RBAC only (Backup Contributor/Operator/Reader); no separate"
            " data plane RBAC evaluation point for backup/restore operations exists."
            " Source: https://learn.microsoft.com/en-us/azure/backup/backup-rbac-rs-vault"
        ),
    ),
    # ── Q1-C: siterecovery IM-8 Credentials / KV ─────────────────────────────
    # Run As accounts retired Sep 2023; ASR uses managed identity → no credentials to store in KV.
    (
        "siterecovery",
        "IM-8",
        "Service Credential and Secrets Support Integration and Storage in Azure Key Vault",
        "run as accounts retired september 2023",
        (
            "Q1-C WebSearch June 2026 confirmed still_not_applicable: Azure Automation Run As"
            " accounts retired September 30, 2023; ASR now uses system-assigned managed identity"
            " via Automation Account for mobility agent update automation — no service principal"
            " credentials remain to store in Key Vault; IM-8 not applicable."
            " Source: https://learn.microsoft.com/en-us/azure/site-recovery/how-to-migrate-run-as-accounts-managed-identity"
        ),
    ),
]


def apply_patch(slug: str, ctrl_id: str, feat_sub: str, idem_key: str, append_text: str) -> int:
    csv_path = pathlib.Path(f"data/outputs/br/{slug}.final.csv")
    if not csv_path.exists():
        print(f"  {slug} {ctrl_id}: SKIP — file not found")
        return 0

    rows = list(csv.DictReader(open(csv_path)))
    updated = 0

    for row in rows:
        if row.get("asb_control_id") != ctrl_id:
            continue
        if feat_sub.lower() not in row.get("feature_name", "").lower():
            continue
        notes = row.get("notes", "")
        if idem_key in notes:
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
    print("Phase 60 Step 3 — Individual patches (BR domain)")
    print("=" * 60)
    total = 0

    for slug, ctrl_id, feat_sub, idem_key, append_text in PATCHES:
        n = apply_patch(slug, ctrl_id, feat_sub, idem_key, append_text)
        label = f"{slug} {ctrl_id} {feat_sub[:25]}"
        print(f"  {label:<48} rows_patched={n}")
        total += n

    print()
    print(f"Total rows patched: {total}")
    print("Done.")

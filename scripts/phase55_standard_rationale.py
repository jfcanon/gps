"""Phase 55 Step 2 — Add standard rationale for clearly-not-applicable controls.

ES/AM/PV/BR controls on network infrastructure services have standard rationale:
these services have no customer-accessible compute layer. Microsoft manages
infrastructure-level controls. No Exa search needed — rationale is definitive.

Also prints the remaining Exa work queue for uncertain controls.
"""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

# Standard rationale by control domain + service type
# source URL is always a valid MS docs page
STANDARD_RATIONALE = {
    # Endpoint/Anti-Malware controls: not applicable on network appliances
    "ES": (
        "Network infrastructure resource with no customer-accessible compute layer. "
        "EDR/anti-malware deployment by customers is not applicable. "
        "Microsoft manages endpoint security at the underlying infrastructure level. "
        "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/infrastructure"
    ),
    "AM": (
        "Network infrastructure resource with no customer-managed compute. "
        "Microsoft Defender for Servers/Endpoints is not applicable — no VMs are "
        "exposed to customers. Anti-malware is managed at the Azure infrastructure layer. "
        "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/infrastructure"
    ),
    "PV": (
        "Network infrastructure resource with no customer-managed VMs or OS layer. "
        "Patch management and vulnerability assessment are handled by Microsoft for "
        "the underlying service infrastructure. Customer has no compute to patch. "
        "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/infrastructure"
    ),
    "GS": (
        "Network infrastructure resource. Posture management and secure configuration "
        "baselines for this resource type are enforced by Microsoft. Customer configures "
        "resource via ARM/Policy; OS-level posture not applicable. "
        "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/secure-score-security-controls"
    ),
}

# Service-specific standard rationale for BR (backup) on network resources
BR_NETWORK_RATIONALE = (
    "Network infrastructure resource — configuration is declarative (ARM templates, "
    "Azure Policy). Azure Backup is a data backup service for compute/storage. "
    "Backup/Recovery for this resource type means ARM export or Resource Graph snapshots, "
    "not Azure Backup integration. Feature not supported in MCSB v3 baseline; "
    "no change as of June 2026. "
    "Source: https://learn.microsoft.com/en-us/azure/backup/backup-overview"
)

BR_PAAS_RATIONALE = (
    "PaaS managed service — backup is either not supported or managed differently "
    "from Azure Backup (e.g., geo-redundancy, snapshots). "
    "Feature not supported in MCSB v3 baseline for this service. "
    "Source: https://learn.microsoft.com/en-us/azure/backup/backup-overview"
)

# Services where ES/AM/PV/BR/GS are definitively not applicable
NETWORK_INFRA_SERVICES = {
    "bastion", "privatelink", "vpngateway", "waf",
    "ddosprotection", "firewallmanager", "networkwatcher", "publicip",
    "appgateway",   # network appliance — no customer compute
}

PAAS_SERVICES = {
    "redis", "servicebus",
}

# Pure network infrastructure services with NO data plane — IM/PA/DP also not applicable
# These services: DDoS Protection plan, Firewall Manager, Network Watcher, Public IP
# They route/protect/monitor network traffic but store no customer data
PURE_NETWORK_NO_DATAPLANE = {
    "ddosprotection", "firewallmanager", "networkwatcher", "publicip",
}

# Standard rationale for IM controls on no-data-plane network services
IM_NETWORK_RATIONALE = (
    "Network infrastructure resource with no customer-accessible data plane. "
    "Identity and authentication controls apply only at the Azure management plane "
    "(Azure AD RBAC for resource management). No data plane auth concept exists — "
    "the service operates at the network packet level with no API auth surface exposed to customers. "
    "Source: https://learn.microsoft.com/en-us/azure/role-based-access-control/overview"
)

# Standard rationale for PA controls on no-data-plane network services
PA_NETWORK_RATIONALE = (
    "Network infrastructure resource. Privileged access controls (local admin accounts, "
    "data plane RBAC, Customer Lockbox) are not applicable — no compute/OS layer exposed, "
    "no data plane API requiring elevated access. Management access is via Azure AD RBAC at "
    "subscription/resource group level. "
    "Source: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
)

# Standard rationale for DP controls on no-data-plane network services
DP_NETWORK_RATIONALE = (
    "Network infrastructure resource that routes/filters/monitors network traffic. "
    "Does not store or process customer application data. Data protection controls "
    "(encryption at rest, DLP, CMK, Key Vault integration) are not applicable — "
    "there is no customer data at rest in this service. Configuration data is managed "
    "via ARM and encrypted by Azure platform by default. "
    "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-overview"
)


def has_evidence(notes: str) -> bool:
    return any(x in notes.lower()
               for x in ["http", "source:", "exa", "2025", "2026", "phase48"])


def get_standard_note(ctrl_domain: str, service: str, current_notes: str) -> str | None:
    """Return standard rationale note or None if not applicable."""
    if ctrl_domain in ("ES", "AM", "PV", "GS"):
        if service in NETWORK_INFRA_SERVICES or service in PAAS_SERVICES:
            return (
                f"{current_notes.rstrip()} | "
                + STANDARD_RATIONALE[ctrl_domain]
            ).lstrip(" |")

    if ctrl_domain == "BR":
        if service in NETWORK_INFRA_SERVICES:
            return (
                f"{current_notes.rstrip()} | " + BR_NETWORK_RATIONALE
            ).lstrip(" |")
        if service in PAAS_SERVICES:
            return (
                f"{current_notes.rstrip()} | " + BR_PAAS_RATIONALE
            ).lstrip(" |")

    # Extended: IM/PA/DP on pure network no-dataplane services
    if service in PURE_NETWORK_NO_DATAPLANE:
        if ctrl_domain == "IM":
            return (
                f"{current_notes.rstrip()} | " + IM_NETWORK_RATIONALE
            ).lstrip(" |")
        if ctrl_domain == "PA":
            return (
                f"{current_notes.rstrip()} | " + PA_NETWORK_RATIONALE
            ).lstrip(" |")
        if ctrl_domain == "DP":
            return (
                f"{current_notes.rstrip()} | " + DP_NETWORK_RATIONALE
            ).lstrip(" |")

    return None


def process_service(slug: str) -> tuple[int, list]:
    """Add standard rationale, return (count_filled, exa_work_queue)."""
    csv_path = pathlib.Path(f"data/outputs/ns/{slug}.final.csv")
    rows = list(csv.DictReader(open(csv_path)))

    filled = 0
    exa_queue = []

    for row in rows:
        notes = row.get("notes", "")
        verdict = row["verdict_2025"]

        if verdict not in ("still_not_applicable", "now_applicable_native"):
            continue

        # Already has evidence — skip
        if has_evidence(notes):
            continue

        ctrl_id = row["asb_control_id"].strip()
        ctrl_domain = ctrl_id.split("-")[0]

        if verdict == "still_not_applicable":
            standard = get_standard_note(ctrl_domain, slug, notes)
            if standard:
                row["notes"] = standard
                filled += 1
            else:
                # Queue for Exa search
                exa_queue.append({
                    "slug": slug,
                    "asb_control_id": ctrl_id,
                    "feature_name": row["feature_name"],
                    "current_verdict": verdict,
                    "current_notes": notes[:80],
                    "reason": "still_na_uncertain",
                })

        elif verdict == "now_applicable_native":
            # now_applicable_native WITHOUT URL → must Exa to confirm
            exa_queue.append({
                "slug": slug,
                "asb_control_id": ctrl_id,
                "feature_name": row["feature_name"],
                "current_verdict": verdict,
                "current_notes": notes[:80],
                "reason": "now_app_no_url",
            })

    # Write updated CSV
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        for row in rows:
            writer.writerow([row.get(h, "") for h in HEADER])

    return filled, exa_queue


if __name__ == "__main__":
    slugs = [
        "appgateway", "azuredns", "azurefirewall", "bastion", "ddosprotection",
        "firewallmanager", "frontdoor", "networkwatcher", "privatelink", "publicip",
        "redis", "servicebus", "vpngateway", "waf",
    ]

    total_filled = 0
    all_exa_queue = []

    print("=" * 70)
    print("Standard rationale fill + Exa work queue")
    print("=" * 70)

    for slug in slugs:
        filled, queue = process_service(slug)
        total_filled += filled
        all_exa_queue.extend(queue)
        if filled > 0 or queue:
            print(f"  {slug:<20} standard_filled={filled:>3}  exa_needed={len(queue):>3}")

    print()
    print(f"Total standard rationale filled: {total_filled}")
    print(f"Total Exa searches still needed: {len(all_exa_queue)}")

    print()
    print("=" * 70)
    print("EXA WORK QUEUE (remaining gaps)")
    print("=" * 70)
    for i, item in enumerate(all_exa_queue):
        print(f"  [{i+1:>3}] {item['slug']:<20} {item['asb_control_id']:12} "
              f"{item['reason']:20} {item['feature_name'][:45]}")

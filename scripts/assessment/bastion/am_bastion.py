"""
Asset Management checks for Azure Bastion (MCSB v3).

AM-2 Azure Policy Support: LIVE-DIRECT — tags proxy.
    final_verdict=customer (True/False). feature_supported=True, enabled_by_default=False.
    Tags non-empty → PASS (Azure Policy governance visible via tag enforcement policies).
    Tags empty → FAIL.

AM-5 Defender AAC: UNKNOWN static.
    feature_supported=Not Applicable, final_verdict=not_applicable.
    Adaptive Application Controls target VMs and Arc servers with customer compute.
    Bastion is a managed jump host PaaS service; no customer-accessible compute. not_applicable.

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (AM-2 only).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"


def _get_bastions(client, resource_group, bastion_name):
    if bastion_name and resource_group:
        return [client.bastion_hosts.get(resource_group, bastion_name)]
    elif resource_group:
        return list(client.bastion_hosts.list(resource_group))
    else:
        return list(client.bastion_hosts.list_all())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(client, resource_group, bastion_name)
    except Exception as e:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "AM-2",
            "feature": "Azure Policy Support",
            "status": "UNKNOWN",
            "actual_value": f"Error listing bastion hosts: {e}",
            "expected_value": "bastion.tags non-empty",
            "evidence_url": _EVIDENCE,
        }

    if not bastions:
        return {
            "resource": bastion_name or resource_group or "all",
            "control_id": "AM-2",
            "feature": "Azure Policy Support",
            "status": "UNKNOWN",
            "actual_value": "No Azure Bastion hosts found in scope",
            "expected_value": "bastion.tags non-empty",
            "evidence_url": _EVIDENCE,
        }

    tagged = [b for b in bastions if b.tags]
    status = "PASS" if tagged else "FAIL"
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "AM-2",
        "feature": "Azure Policy Support",
        "status": status,
        "actual_value": f"{len(tagged)}/{len(bastions)} bastion hosts have tags",
        "expected_value": "bastion.tags non-empty",
        "evidence_url": _EVIDENCE,
    }


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "AM-5",
        "feature": "Microsoft Defender for Cloud — Adaptive Application Controls",
        "status": "UNKNOWN",
        "actual_value": "feature_supported=Not Applicable in MCSB v3 baseline. Adaptive Application Controls target VMs and Azure Arc-enabled servers with customer-accessible compute. Azure Bastion is a managed PaaS jump host — no customer compute substrate. not_applicable.",
        "expected_value": "N/A — feature_supported=Not Applicable; AAC not applicable to Bastion",
        "evidence_url": _EVIDENCE,
    }

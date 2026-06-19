"""
Asset Management checks for Azure Front Door (MCSB v3).

AM-2: True, True → tags proxy → LIVE check.
AM-5: Not Applicable — PaaS CDN; no compute for Adaptive Application Controls.

Read-only. Zero ARM writes.
"""
from azure.mgmt.frontdoor import FrontDoorManagementClient


def _get_front_doors(client: FrontDoorManagementClient, resource_group: str | None, front_door_name: str | None) -> list:
    if resource_group and front_door_name:
        return [client.front_doors.get(resource_group, front_door_name)]
    elif resource_group:
        return list(client.front_doors.list_by_resource_group(resource_group))
    else:
        return list(client.front_doors.list())


def check_am2_policy(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    base = {
        "control_id": "AM-2",
        "feature": "Use Only Approved Azure Services — Azure Policy Support",
        "expected_value": "Resource tags present (proxy for Azure Policy governance tagging)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview",
    }
    try:
        client = FrontDoorManagementClient(credential, subscription_id)
        front_doors = _get_front_doors(client, resource_group, front_door_name)
        if not front_doors:
            return {**base, "resource": front_door_name or "none", "status": "PASS",
                    "actual_value": "No Front Door instances found in scope"}
        first_pass = None
        for fd in front_doors:
            tags = getattr(fd, "tags", None) or {}
            if tags:
                r = {**base, "resource": fd.name, "status": "PASS",
                     "actual_value": f"tags present: {list(tags.keys())}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": fd.name, "status": "FAIL",
                        "actual_value": (
                            "tags={} — no resource tags; Azure Policy governance tagging not confirmed. "
                            "AFD is a globally distributed resource — apply environment/owner/cost-center tags via Azure Policy."
                        )}
        return first_pass
    except Exception as e:
        return {**base, "resource": front_door_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_am5_defender_aac(credential, subscription_id: str, resource_group: str | None, front_door_name: str | None) -> dict:
    return {
        "resource": front_door_name or "all",
        "control_id": "AM-5",
        "feature": "Use Only Approved Applications in Virtual Machine — Defender for Cloud AAC",
        "status": "UNKNOWN",
        "actual_value": "PaaS CDN/WAF service — Adaptive Application Controls target VMs and Arc-enabled servers; not applicable to Azure Front Door.",
        "expected_value": "N/A — PaaS; AAC not applicable",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/adaptive-application-controls",
    }

"""
Privileged Access checks for Azure Event Grid (MCSB v3).

PA-7: Data plane RBAC via Event Grid built-in roles → UNKNOWN (not per-topic ARM readable).

Read-only. Zero ARM writes.
"""


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Event Grid data plane RBAC uses built-in roles: EventGrid Data Sender, EventGrid Contributor, EventGrid Reader. Role assignments not readable per-topic via Event Grid ARM. Use azure-mgmt-authorization for enumeration.",
        "expected_value": "Data plane roles follow least-privilege (Data Sender, not Contributor)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/security-authorization",
    }

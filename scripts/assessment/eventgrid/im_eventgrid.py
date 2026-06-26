"""
Identity Management checks for Azure Event Grid (MCSB v3).

IM-1 AAD: topic.disable_local_auth=True → SAS/shared access key auth disabled → PASS.
IM-1 local auth: same property.
IM-3 MI: topic.identity assigned → PASS.
IM-3 SP: ARM RBAC — not per-topic ARM → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.eventgrid import EventGridManagementClient


def _get_topics(client: EventGridManagementClient, resource_group: str | None, topic_name: str | None) -> list:
    if resource_group and topic_name:
        return [client.topics.get(resource_group, topic_name)]
    elif resource_group:
        return list(client.topics.list_by_resource_group(resource_group))
    else:
        return list(client.topics.list_by_subscription())


def check_im1_aad_auth(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — AAD Auth Required (Disable SAS Keys)",
        "expected_value": "topic.disable_local_auth=True (SAS key auth disabled)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/authenticate-with-microsoft-entra-id",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            disable_local = getattr(topic, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — SAS key auth disabled; Entra ID only"}
                first_pass = first_pass or r
            elif disable_local is False:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — SAS key authentication enabled"}
            else:
                return {**base, "resource": topic.name, "status": "UNKNOWN",
                        "actual_value": "disable_local_auth not returned — assume SAS enabled (default)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "IM-1",
        "feature": "Use Centralized Identity and Authentication System — Disable Local Auth Methods",
        "expected_value": "topic.disable_local_auth=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/authenticate-with-microsoft-entra-id",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            disable_local = getattr(topic, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — local auth methods disabled"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": f"disable_local_auth={disable_local} — SAS key auth still available"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    base = {
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication",
        "expected_value": "topic.identity.type assigned (SystemAssigned or UserAssigned)",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/managed-service-identity",
    }
    try:
        client = EventGridManagementClient(credential, subscription_id)
        topics = _get_topics(client, resource_group, topic_name)
        if not topics:
            return {**base, "resource": topic_name or "none", "status": "PASS",
                    "actual_value": "No Event Grid topics found in scope"}
        first_pass = None
        for topic in topics:
            identity = getattr(topic, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": topic.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": topic.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": topic_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id: str, resource_group: str | None, topic_name: str | None) -> dict:
    return {
        "resource": topic_name or "all",
        "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities for Azure Resource Authentication — Service Principal",
        "status": "UNKNOWN",
        "actual_value": "Service principal role assignments not readable per-topic via Event Grid ARM. Use azure-mgmt-authorization for enumeration.",
        "expected_value": "Prefer managed identity over service principal",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/event-grid/managed-service-identity",
    }

"""
Privileged Access checks for Azure Functions (MCSB v3).

PA-7: Data plane RBAC via Entra ID (functions invoke via function keys or Entra auth) → UNKNOWN.
PA-8: Customer Lockbox — App Service/Functions in supported list; subscription-level → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Function invocation uses function keys (local auth) or EasyAuth (Entra). Data plane RBAC is not ARM-readable per function. Prefer Entra-based auth (EasyAuth v2) over function keys. Role assignments via azure-mgmt-authorization.",
        "expected_value": "Function invocation via Entra auth (EasyAuth v2 enabled) rather than function keys",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
    }


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure Functions (via App Service) is in the Customer Lockbox supported services list. Lockbox enablement is at subscription level — not readable per function via ARM.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }

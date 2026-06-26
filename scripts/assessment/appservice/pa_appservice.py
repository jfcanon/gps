"""
Privileged Access checks for Azure App Service (MCSB v3).

PA-8: Customer Lockbox — App Service in supported list; subscription-level only → UNKNOWN.

Read-only. Zero ARM writes.
"""


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, site_name: str | None) -> dict:
    return {
        "resource": site_name or "all",
        "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Azure App Service is in the Customer Lockbox supported services list. Lockbox enablement is at subscription level — not readable per-site via ARM. Check via Azure Portal > Customer Lockbox.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability",
    }

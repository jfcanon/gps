"""
Privileged Access checks for Azure Public IP (MCSB v3).

PA-1/7/8: No local admin, no data plane, not in Lockbox list → all UNKNOWN static.

Read-only. Zero ARM writes.
"""


def check_pa1_local_admin(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "PA-1", "feature": "Separate and Limit Highly Privileged/Administrative Users — Disable Local Admin", "status": "UNKNOWN", "actual_value": "Azure Public IP is a managed network resource with no local admin account concept. All operations require Entra ID identity via ARM RBAC (Network Contributor or Owner).", "expected_value": "N/A — no local admin; ARM RBAC only", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_pa7_rbac_data_plane(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "PA-7", "feature": "Follow Just Enough Administration Principle — Azure RBAC for Data Plane", "status": "UNKNOWN", "actual_value": "Azure Public IP has no customer-accessible data plane requiring RBAC. Management plane access is controlled via ARM RBAC (Network Contributor role for assignment). No separate data-plane RBAC configuration exists.", "expected_value": "N/A — no data plane; ARM RBAC controls management access", "evidence_url": "https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses"}


def check_pa8_customer_lockbox(credential, subscription_id: str, resource_group: str | None, public_ip_name: str | None) -> dict:
    return {"resource": public_ip_name or "all", "control_id": "PA-8", "feature": "Determine Access Process for Microsoft Support — Customer Lockbox", "status": "UNKNOWN", "actual_value": "Azure Public IP is not listed in the Customer Lockbox supported services GA list. Microsoft support access to PIP configuration is governed by standard Microsoft support policies.", "expected_value": "N/A — PIP not in Customer Lockbox supported services list", "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview#supported-services-and-scenarios-in-general-availability"}

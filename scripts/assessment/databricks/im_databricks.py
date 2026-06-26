"""
Identity Management checks for Azure Databricks (MCSB v3).

IM-1 AAD: Databricks uses Entra ID (AAD) natively — local auth = PAT tokens. UNKNOWN.
IM-3 SP: UNKNOWN.
IM-7 CA: UNKNOWN (tenant-level).
IM-8 KV: workspace secrets backed by Databricks Secret Scopes → UNKNOWN.
PA-7: UNKNOWN (ARM RBAC).
PA-8: UNKNOWN (subscription-level).

Read-only. Zero ARM writes.
"""


def check_im1_aad_auth(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
            "status": "UNKNOWN",
            "actual_value": "Azure Databricks uses Entra ID (AAD) for authentication by default. PAT (Personal Access Tokens) provide local auth — disable via Databricks account settings (admin console), not ARM.",
            "expected_value": "PAT generation disabled in workspace settings; Entra-only access",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-groups/service-principals"}


def check_im1_local_auth_methods(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — Disable Local Auth (PAT)",
            "status": "UNKNOWN",
            "actual_value": "PAT token enablement is controlled in Databricks admin console (workspace settings), not in the ARM resource. Not ARM-readable.",
            "expected_value": "PAT generation disabled; use OAuth/Entra tokens only",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/access-control/tokens"}


def check_im3_service_principals(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-3",
            "feature": "Use Azure AD Managed Identities — Service Principals",
            "status": "UNKNOWN",
            "actual_value": "Service principals for Databricks access are managed via Entra ID and Databricks admin console. Not ARM-readable per workspace.",
            "expected_value": "Prefer managed identity over service principal where possible",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/users-groups/service-principals"}


def check_im7_conditional_access(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-7",
            "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
            "status": "UNKNOWN",
            "actual_value": "CA policies applied to Azure Databricks are Entra ID tenant-level. Not ARM-readable per workspace.",
            "expected_value": "CA policies applied to Azure Databricks application registration",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/baseline"}


def check_im8_keyvault_secrets(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-8",
            "feature": "Restrict the Exposure of Credentials and Secrets — Secret Scopes via Key Vault",
            "status": "UNKNOWN",
            "actual_value": "Databricks Secret Scopes can back secrets with Azure Key Vault (AKV-backed secret scope). Configured via Databricks REST API, not ARM resource.",
            "expected_value": "AKV-backed secret scopes used instead of Databricks-backed (native) scopes",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/security/secrets/secret-scopes"}


def check_pa7_rbac_data_plane(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-7",
            "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
            "status": "UNKNOWN",
            "actual_value": "Databricks data plane access (clusters, notebooks, jobs) uses Databricks ACLs managed in admin console, not ARM RBAC. Not ARM-readable per workspace.",
            "expected_value": "Least-privilege Databricks ACLs; use groups not individual users",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/access-control/cluster-acl"}


def check_pa8_customer_lockbox(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-8",
            "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
            "status": "UNKNOWN",
            "actual_value": "Customer Lockbox for Azure Databricks is subscription-level. Not readable per workspace via ARM.",
            "expected_value": "Customer Lockbox enabled at subscription level",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"}

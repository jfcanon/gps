"""
Identity Management checks for Azure Database Migration Service (MCSB v3).

IM-1 AAD: DMS uses ARM RBAC for service management → PASS.
IM-3 SP: Source/target DB credentials stored as task params → UNKNOWN.
PA-7: ARM RBAC for DMS management → PASS.

Read-only. Zero ARM writes.
"""
from azure.mgmt.datamigration import DataMigrationManagementClient


def check_im1_aad_auth(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — AAD Auth",
            "status": "PASS",
            "actual_value": "Azure Database Migration Service management plane uses AAD authentication. Creating and managing DMS services and migration tasks requires AAD-authenticated ARM calls (az dms / REST API).",
            "expected_value": "AAD auth for DMS management plane (ARM RBAC)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/security-baseline#im-1-use-centralized-identity-and-authentication-system"}


def check_im3_service_principals(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-3",
            "feature": "Use Azure AD Managed Identities — Service Principals for Source/Target DB Credentials",
            "status": "UNKNOWN",
            "actual_value": "DMS migration tasks receive source and target database connection strings (with credentials) as task parameters at runtime. These are stored encrypted per task but are not ARM-readable. Prefer Key Vault references in IaC scripts.",
            "expected_value": "Source/target DB credentials referenced from Key Vault by IaC tooling; not hardcoded",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/tutorial-sql-server-azure-sql-online"}


def check_pa7_rbac_data_plane(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-7",
            "feature": "Follow Just Enough Administration — ARM RBAC for DMS",
            "status": "PASS",
            "actual_value": "Azure Database Migration Service uses Azure ARM RBAC for all management operations. Built-in roles: Contributor and Owner control DMS service and task management.",
            "expected_value": "ARM RBAC controls DMS management (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/security-baseline#pa-7-follow-just-enough-administration-least-privilege-principle"}

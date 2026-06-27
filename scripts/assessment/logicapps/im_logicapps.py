"""
Identity Management checks for Azure Logic Apps (MCSB v3).

IM-1 AAD: Logic Apps OAuth connectors use AAD → check workflow.identity not None.
IM-1 local: Logic Apps SAS keys (shared access signature) for triggers → UNKNOWN.
IM-3 MI: workflow.identity.type assigned → PASS.
IM-3 SP: UNKNOWN.
IM-8: KV for connector credentials → UNKNOWN.
PA-8: Customer Lockbox → UNKNOWN.

Read-only. Zero ARM writes.
"""
from azure.mgmt.logic import LogicManagementClient


def _get_workflows(client, rg, name):
    if rg and name:
        return [client.workflows.get(rg, name)]
    elif rg:
        return list(client.workflows.list_by_resource_group(rg))
    else:
        return list(client.workflows.list_by_subscription())


def check_im1_aad_auth(credential, subscription_id, resource_group, workflow_name):
    base = {"control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — AAD Auth for Data Plane",
            "expected_value": "workflow.identity.type assigned (managed identity for connector auth)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/create-managed-service-identity"}
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = _get_workflows(client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            identity = getattr(wf, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type} — managed identity available for AAD-authenticated connector calls"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity; connectors may use service keys"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-1",
            "feature": "Use Centralized Identity and Authentication System — Disable Local Auth (SAS keys)",
            "status": "UNKNOWN",
            "actual_value": "Logic Apps trigger SAS keys (Shared Access Signatures) are local auth. Disabling SAS and enforcing OAuth/managed identity is done per-connector, not ARM-readable per workflow.",
            "expected_value": "Connectors use OAuth (managed identity), not SAS keys",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/create-managed-service-identity"}


def check_im3_managed_identities(credential, subscription_id, resource_group, workflow_name):
    base = {"control_id": "IM-3", "feature": "Use Azure AD Managed Identities — Managed Identity Assigned",
            "expected_value": "workflow.identity.type assigned",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/create-managed-service-identity"}
    try:
        client = LogicManagementClient(credential, subscription_id)
        workflows = _get_workflows(client, resource_group, workflow_name)
        if not workflows:
            return {**base, "resource": workflow_name or "none", "status": "PASS", "actual_value": "No workflows found"}
        first_pass = None
        for wf in workflows:
            identity = getattr(wf, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": wf.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": wf.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity"}
        return first_pass
    except Exception as e:
        return {**base, "resource": workflow_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-3", "feature": "Use Azure AD Managed Identities — Service Principals",
            "status": "UNKNOWN",
            "actual_value": "Service principal usage in Logic Apps connectors is at connection/action level. Not ARM-readable per workflow.",
            "expected_value": "Prefer managed identity over service principal in connector auth",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/create-managed-service-identity"}


def check_im8_keyvault_secrets(c, s, r, n):
    return {"resource": n or "all", "control_id": "IM-8", "feature": "Restrict the Exposure of Credentials and Secrets — KV Integration",
            "status": "UNKNOWN",
            "actual_value": "Logic Apps can reference Azure Key Vault for connector credentials. This is configured at the connection/action level inside the workflow definition, not on the workflow ARM resource.",
            "expected_value": "Logic App connections reference Key Vault for credentials (not inline)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/store-credentials-azure-key-vault"}


def check_pa8_customer_lockbox(c, s, r, n):
    return {"resource": n or "all", "control_id": "PA-8", "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
            "status": "UNKNOWN",
            "actual_value": "Customer Lockbox for Logic Apps is subscription-level. Not readable per workflow via ARM.",
            "expected_value": "Customer Lockbox enabled at subscription level",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"}

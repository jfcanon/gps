"""
Identity Management checks for Azure Cognitive Services (MCSB v3).

IM-1 AAD: disable_local_auth=True → API key auth disabled → PASS.
IM-1 local: same property.
IM-3 MI: account.identity.type assigned → PASS.
IM-3 SP: UNKNOWN (ARM RBAC level).
IM-7 CA: UNKNOWN (tenant-level).
IM-8 KV secrets: UNKNOWN (app-level).
PA-7: UNKNOWN (role assignments).
PA-8: UNKNOWN (subscription-level).

Read-only. Zero ARM writes.
"""
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient


def _get_accounts(client, rg, name):
    if rg and name:
        return [client.accounts.get(rg, name)]
    elif rg:
        return list(client.accounts.list_by_resource_group(rg))
    else:
        return list(client.accounts.list())


def check_im1_aad_auth(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "IM-1", "feature": "Use Centralized Identity and Authentication System — AAD Auth Required",
        "expected_value": "account.properties.disable_local_auth=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/disable-local-auth",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            disable_local = getattr(acct, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True — API key auth disabled; Entra ID required"}
                first_pass = first_pass or r
            elif disable_local is False:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": "disable_local_auth=False — API key authentication enabled"}
            else:
                return {**base, "resource": acct.name, "status": "UNKNOWN",
                        "actual_value": "disable_local_auth not returned — API key auth may be enabled (default)"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im1_local_auth_methods(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "IM-1", "feature": "Disable Local Authentication Methods",
        "expected_value": "account.properties.disable_local_auth=True",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/disable-local-auth",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            disable_local = getattr(acct, "disable_local_auth", None)
            if disable_local is True:
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": "disable_local_auth=True"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"disable_local_auth={disable_local} — local API key still enabled"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_managed_identities(credential, subscription_id, resource_group, account_name):
    base = {
        "control_id": "IM-3", "feature": "Use Azure AD Managed Identities — Managed Identity Assigned",
        "expected_value": "account.identity.type assigned",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/authentication",
    }
    try:
        client = CognitiveServicesManagementClient(credential, subscription_id)
        accounts = _get_accounts(client, resource_group, account_name)
        if not accounts:
            return {**base, "resource": account_name or "none", "status": "PASS", "actual_value": "No accounts found"}
        first_pass = None
        for acct in accounts:
            identity = getattr(acct, "identity", None)
            identity_type = str(getattr(identity, "type", "None")) if identity else "None"
            if identity and identity_type.lower() not in ("none", ""):
                r = {**base, "resource": acct.name, "status": "PASS",
                     "actual_value": f"identity.type={identity_type}"}
                first_pass = first_pass or r
            else:
                return {**base, "resource": acct.name, "status": "FAIL",
                        "actual_value": f"identity.type={identity_type} — no managed identity assigned"}
        return first_pass
    except Exception as e:
        return {**base, "resource": account_name or "unknown", "status": "UNKNOWN", "actual_value": str(e)}


def check_im3_service_principals(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "IM-3",
        "feature": "Use Azure AD Managed Identities — Service Principals",
        "status": "UNKNOWN",
        "actual_value": "Service principal role assignments not readable per account via Cognitive Services ARM.",
        "expected_value": "Prefer managed identity over service principal credentials",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/authentication",
    }


def check_im7_conditional_access(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "IM-7",
        "feature": "Restrict Resource Access Based on Conditions — Conditional Access",
        "status": "UNKNOWN",
        "actual_value": "Conditional Access policies are Entra ID tenant-level. Not readable per Cognitive Services account via ARM.",
        "expected_value": "CA policies applied to Cognitive Services application registration",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline",
    }


def check_im8_keyvault_secrets(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "IM-8",
        "feature": "Restrict the Exposure of Credentials and Secrets",
        "status": "UNKNOWN",
        "actual_value": "Cognitive Services API keys should be stored in Azure Key Vault by consuming applications. This is an application-level control — not verifiable via Cognitive Services ARM.",
        "expected_value": "API keys stored in Key Vault; applications use managed identity or KV references",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/security-baseline#im-8-restrict-the-exposure-of-credential-and-secrets",
    }


def check_pa7_rbac_data_plane(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "PA-7",
        "feature": "Follow Just Enough Administration Principle — RBAC for Data Plane",
        "status": "UNKNOWN",
        "actual_value": "Cognitive Services data plane RBAC: Cognitive Services User, Contributor, Reader. Role assignments not per-account readable via Cognitive Services ARM.",
        "expected_value": "Least-privilege data plane roles",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/cognitive-services/authentication#azure-active-directory-authentication",
    }


def check_pa8_customer_lockbox(credential, subscription_id, resource_group, account_name):
    return {
        "resource": account_name or "all", "control_id": "PA-8",
        "feature": "Determine Access Process for Microsoft Support — Customer Lockbox",
        "status": "UNKNOWN",
        "actual_value": "Customer Lockbox for Cognitive Services is subscription-level. Not readable per account via ARM.",
        "expected_value": "Customer Lockbox enabled at subscription level",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview",
    }

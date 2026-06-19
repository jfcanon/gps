"""
Data Protection checks for Azure WAF Policy (MCSB v3).

DP-1: LIVE-DIRECT — policy.policy_settings.log_scrubbing (sensitive data masking in WAF logs).
DP-2: UNKNOWN static — WAF stores no persistent customer data.
DP-3: LIVE-INDIRECT — App Gateway ssl_policy.min_protocol_version.
DP-4/5/6: UNKNOWN static — WAF stores no customer data at rest.
DP-7: LIVE-INDIRECT — App Gateway ssl_certificates[].key_vault_secret_id.

Read-only. Zero ARM writes.
"""
from azure.mgmt.network import NetworkManagementClient

_EVIDENCE_WAF = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"
_EVIDENCE_DP1 = "https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/waf-sensitive-data-protection-configure"
_EVIDENCE_DP3 = "https://learn.microsoft.com/en-us/azure/application-gateway/ssl-overview"
_EVIDENCE_DP7 = "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs"
_NO_DATA_NOTE = "WAF does not store customer data at rest (confirmed in MCSB v3 baseline); "


def _get_waf_policies(client, resource_group, policy_name):
    if resource_group and policy_name:
        return [client.web_application_firewall_policies.get(resource_group, policy_name)]
    elif resource_group:
        return list(client.web_application_firewall_policies.list(resource_group))
    else:
        return list(client.web_application_firewall_policies.list_all())


def _get_app_gateways_for_policy(client, policy_id):
    result = []
    for ag in client.application_gateways.list_all():
        fp = getattr(ag, 'firewall_policy', None)
        if fp and getattr(fp, 'id', '').lower() == policy_id.lower():
            result.append(ag)
    return result


def check_dp1_log_scrubbing(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification (Log Scrubbing)",
        "expected_value": "policy_settings.log_scrubbing.state == 'Enabled'",
        "evidence_url": _EVIDENCE_DP1,
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            settings = getattr(policy, 'policy_settings', None)
            scrubbing = getattr(settings, 'log_scrubbing', None) if settings else None
            if scrubbing is None:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "log_scrubbing not exposed by SDK (requires API version 2022-09-01+); upgrade azure-mgmt-network"}
                first_pass = first_pass or r
                continue
            state = getattr(scrubbing, 'state', None)
            if state == 'Enabled':
                r = {**base, "resource": policy.name, "status": "PASS",
                     "actual_value": f"Log scrubbing Enabled; {len(getattr(scrubbing, 'scrubbing_rules', None) or [])} rule(s) configured"}
            else:
                return {**base, "resource": policy.name, "status": "FAIL",
                        "actual_value": f"Log scrubbing state={state!r}; sensitive data may appear in WAF logs"}
            first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No policies found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": _NO_DATA_NOTE + "DLP solutions target services with persistent data stores. WAF is a routing/inspection service; no DLP applicable.",
        "expected_value": "N/A — WAF stores no customer data",
        "evidence_url": _EVIDENCE_WAF,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption (TLS)",
        "expected_value": "App Gateway ssl_policy.min_protocol_version in (TLSv1_2, TLSv1_3)",
        "evidence_url": _EVIDENCE_DP3,
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                ssl_policy = getattr(ag, 'ssl_policy', None)
                min_proto = getattr(ssl_policy, 'min_protocol_version', None) if ssl_policy else None
                if min_proto in ('TLSv1_2', 'TLSv1_3'):
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"AG {ag.name}: min_protocol_version={min_proto}"}
                else:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"AG {ag.name}: ssl_policy.min_protocol_version={min_proto!r}; "
                                            "default Predefined policy may allow TLS 1.0/1.1; set Custom policy with TLSv1_2 minimum"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "UNKNOWN",
        "actual_value": _NO_DATA_NOTE + "No customer content stored at rest by WAF policy resource. Platform key encryption not applicable.",
        "expected_value": "N/A — WAF stores no customer data at rest",
        "evidence_url": _EVIDENCE_WAF,
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": _NO_DATA_NOTE + "CMK encryption requires customer data at rest. WAF has no customer data store. Not applicable.",
        "expected_value": "N/A — WAF stores no customer data at rest; CMK not applicable",
        "evidence_url": _EVIDENCE_WAF,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    return {
        "resource": policy_name or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": _NO_DATA_NOTE + "WAF has no customer-managed keys to store in KV. Not applicable.",
        "expected_value": "N/A — not_applicable in MCSB v3 baseline",
        "evidence_url": _EVIDENCE_WAF,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, policy_name: str | None) -> dict:
    base = {
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "expected_value": "App Gateway ssl_certificates[].key_vault_secret_id set (KV-backed TLS cert)",
        "evidence_url": _EVIDENCE_DP7,
    }
    try:
        client = NetworkManagementClient(credential, subscription_id)
        policies = _get_waf_policies(client, resource_group, policy_name)
        if not policies:
            return {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                    "actual_value": "No WAF policies found"}

        first_pass = None
        for policy in policies:
            ags = _get_app_gateways_for_policy(client, policy.id)
            if not ags:
                r = {**base, "resource": policy.name, "status": "UNKNOWN",
                     "actual_value": "Policy not attached to any Application Gateway"}
                first_pass = first_pass or r
                continue
            for ag in ags:
                certs = getattr(ag, 'ssl_certificates', None) or []
                has_kv = any(getattr(c, 'key_vault_secret_id', None) for c in certs)
                if has_kv:
                    r = {**base, "resource": policy.name, "status": "PASS",
                         "actual_value": f"AG {ag.name}: Key Vault-backed TLS certificate present"}
                else:
                    return {**base, "resource": policy.name, "status": "FAIL",
                            "actual_value": f"AG {ag.name}: {len(certs)} cert(s) found; none have key_vault_secret_id set; certs uploaded directly"}
                first_pass = first_pass or r
        return first_pass or {**base, "resource": policy_name or "all", "status": "UNKNOWN",
                              "actual_value": "No App Gateway associations found"}
    except Exception as e:
        return {**base, "resource": policy_name or "all", "status": "UNKNOWN", "actual_value": str(e)}

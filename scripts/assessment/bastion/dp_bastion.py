"""
Data Protection checks for Azure Bastion (MCSB v3).

DP-3 Data in Transit Encryption: PASS static (microsoft_managed/True/True).
    Bastion enforces TLS 1.2 for browser-to-bastion (HTTPS) and
    bastion-to-VM (RDP/SSH over TLS) sessions. Platform-enforced; no customer config.

DP-6 Key Management in Azure Key Vault: LIVE→UNKNOWN.
    final_verdict=customer (True/False) — customer can store SSH private keys in KV
    and use them in Bastion native client connections. However, no ARM property on
    BastionHost reflects whether KV-backed SSH keys are in use. This is a
    connection-time behavioral pattern: user selects KV secret at connect time
    via portal or native client. Enumerate bastions to confirm scope, then UNKNOWN.

DP-1/2/4/5/7: UNKNOWN static (not_applicable — Bastion is a jump host; no data store).

Read-only. Zero ARM writes.
SDK: azure-mgmt-network (DP-6 scope enumeration only).
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"
_EVIDENCE_KV = "https://learn.microsoft.com/en-us/azure/bastion/bastion-connect-vm-ssh-linux#akv"
_JUMP_NOTE = "Azure Bastion is a managed jump host — it stores no persistent customer data at rest; "


def _get_bastions(client, resource_group, bastion_name):
    if bastion_name and resource_group:
        return [client.bastion_hosts.get(resource_group, bastion_name)]
    elif resource_group:
        return list(client.bastion_hosts.list(resource_group))
    else:
        return list(client.bastion_hosts.list_all())


def check_dp1_sensitive_data(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": _JUMP_NOTE + "data classification (Purview, MIP) targets services with data stores. Apply DP-1 to the VMs accessed via Bastion, not to Bastion itself. not_applicable.",
        "expected_value": "N/A — Bastion stores no customer data; DP-1 not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": _JUMP_NOTE + "DLP targets services with persistent data stores. Bastion is a jump host with no data store. not_applicable.",
        "expected_value": "N/A — Bastion stores no customer data; DLP not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "PASS",
        "actual_value": "microsoft_managed — Bastion enforces TLS 1.2 for browser-to-bastion (HTTPS) and bastion-to-VM (RDP/SSH tunneled over TLS). No customer configuration required. feature_supported=True, enabled_by_default=True.",
        "expected_value": "microsoft_managed — TLS enforced by platform",
        "evidence_url": _EVIDENCE,
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "UNKNOWN",
        "actual_value": _JUMP_NOTE + "feature_supported=False in MCSB v3 baseline. Bastion has no customer data store to encrypt at rest. not_applicable.",
        "expected_value": "N/A — feature_supported=False; no data at rest in Bastion",
        "evidence_url": _EVIDENCE,
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": _JUMP_NOTE + "CMK requires a customer data store. Bastion has none. Apply CMK to VMs and disks accessed via Bastion if required. not_applicable.",
        "expected_value": "N/A — Bastion stores no customer data; CMK not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    from azure.mgmt.network import NetworkManagementClient
    client = NetworkManagementClient(credential, subscription_id)

    try:
        bastions = _get_bastions(client, resource_group, bastion_name)
        scope_note = f"Found {len(bastions)} bastion host(s) in scope. "
    except Exception as e:
        scope_note = f"Error enumerating bastions ({e}). "

    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": scope_note + "KV SSH key usage for Bastion sessions is a connection-time behavioral pattern — user selects KV secret at connect time via Azure portal or native client (az network bastion ssh --ssh-key-file). No ARM property on BastionHost reflects whether KV-backed SSH keys are in use. Verify via Azure Policy audit rule or manual review of connection workflow documentation.",
        "expected_value": "SSH private keys stored in Azure Key Vault for Bastion native client connections",
        "evidence_url": _EVIDENCE_KV,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, bastion_name: str | None) -> dict:
    return {
        "resource": bastion_name or resource_group or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": _JUMP_NOTE + "feature_supported=Not Applicable in MCSB v3 baseline. Bastion does not manage TLS certificates via Key Vault — Microsoft manages the bastion.azure.com TLS cert. Customer does not configure certificates for the Bastion service itself. not_applicable.",
        "expected_value": "N/A — Bastion does not manage customer TLS certs; not applicable",
        "evidence_url": _EVIDENCE,
    }

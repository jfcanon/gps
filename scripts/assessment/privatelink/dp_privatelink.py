"""
Data Protection checks for Azure Private Link / Private Endpoint (MCSB v3).

DP-1/2/3/4/5/6/7: UNKNOWN static — Private Endpoint is a network relay resource.
    It stores no customer data at rest and performs no encryption itself.
    Encryption, key management, and data classification apply to the
    PaaS service on the other end of the connection (e.g., Storage, SQL DB),
    not to the Private Endpoint NIC resource.

Read-only. Zero ARM writes. No SDK import needed.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
_RELAY_NOTE = "Private Endpoint is a network relay (NIC with private IP); "


def check_dp1_sensitive_data(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE stores no customer data; data classification applies to the connected PaaS service (e.g., Storage, SQL DB), not the PE NIC. not_applicable at PE resource level.",
        "expected_value": "N/A — network relay; no customer data store",
        "evidence_url": _EVIDENCE,
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE stores no persistent customer data; DLP solutions target services with data stores. not_applicable at PE resource level.",
        "expected_value": "N/A — network relay; DLP not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE does not terminate or encrypt traffic itself; encryption is handled by the service on the other end of the connection (e.g., HTTPS to Storage, TLS to SQL). not_applicable at PE resource level.",
        "expected_value": "N/A — encryption handled by connected service, not by PE",
        "evidence_url": _EVIDENCE,
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE stores no customer data at rest; platform key encryption not applicable at PE resource level.",
        "expected_value": "N/A — no customer data at rest in PE resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE stores no customer data at rest; CMK not applicable at PE resource level. Apply CMK to the connected PaaS service if required.",
        "expected_value": "N/A — no customer data at rest; CMK not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE has no customer-managed encryption keys; KV key management not applicable at PE resource level.",
        "expected_value": "N/A — no CMK; KV key management not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, endpoint_name: str | None) -> dict:
    return {
        "resource": endpoint_name or resource_group or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": _RELAY_NOTE + "PE does not manage TLS certificates; certificate management applies to the connected service. not_applicable at PE resource level.",
        "expected_value": "N/A — PE has no certificate management; not applicable",
        "evidence_url": _EVIDENCE,
    }

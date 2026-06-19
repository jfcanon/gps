"""
Data Protection checks for Azure DNS (MCSB v3).

All DP controls: Azure DNS Zone stores DNS records only (A/AAAA/CNAME/MX/TXT/SOA/NS/SRV/PTR/CAA).
No customer PII or business data. DNS protocol is cleartext by design (RFC 1035). No CMK, no KV.
All UNKNOWN static (not_applicable_paas).

Read-only. Zero ARM writes.
"""

_EVIDENCE = "https://learn.microsoft.com/en-us/azure/dns/dns-overview"


def check_dp1_data_classification(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-1",
        "feature": "Sensitive Data Discovery and Classification",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DNS Zone stores DNS records only (A, AAAA, CNAME, MX, TXT, SOA, NS, SRV, PTR, CAA). "
            "No customer PII or business data is stored in the zone resource. "
            "Microsoft Purview and AIP data classification are not applicable to DNS record content."
        ),
        "expected_value": "N/A — DNS records are operational metadata; no customer data in zone resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp2_dlp(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-2",
        "feature": "Data Leakage/Loss Prevention",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS records are operational infrastructure metadata; no DLP product applicable to DNS zone resource. "
            "DNS exfiltration risk (data encoded in DNS queries/responses) is a network-layer concern addressed by "
            "Microsoft Defender for DNS (LT-1 check), not DLP controls on the zone resource itself."
        ),
        "expected_value": "N/A — no DLP for DNS zone; DNS exfiltration addressed by Defender for DNS (LT-1)",
        "evidence_url": _EVIDENCE,
    }


def check_dp3_tls_transit(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-3",
        "feature": "Data in Transit Encryption",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS protocol (RFC 1035) transmits queries and responses in cleartext over UDP/TCP port 53 by design. "
            "Azure DNS does not natively support DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) for public resolvers. "
            "ARM management API for zone CRUD operations uses HTTPS/TLS, but that is the control plane, "
            "not the DNS data plane (query/response). DP-3 is Not Applicable to Azure DNS data plane. "
            "Feature=False in MCSB v3 baseline."
        ),
        "expected_value": "N/A — DNS protocol is cleartext by design (RFC 1035); DoH/DoT not natively supported",
        "evidence_url": _EVIDENCE,
    }


def check_dp4_platform_keys(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-4",
        "feature": "Data at Rest Encryption Using Platform Keys",
        "status": "UNKNOWN",
        "actual_value": (
            "DNS record data is stored on Microsoft-managed DNS infrastructure. "
            "No customer-configurable encryption property exists on the DNS Zone resource. "
            "DP-4 in MCSB v3 targets customer-managed data stores with inspectable encryption configuration. "
            "Not Applicable in MCSB v3 baseline."
        ),
        "expected_value": "N/A — no customer-configurable encryption property on DNS Zone resource",
        "evidence_url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest",
    }


def check_dp5_cmk(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-5",
        "feature": "Data at Rest Encryption Using CMK",
        "status": "UNKNOWN",
        "actual_value": "CMK not supported for Azure DNS Zone. DNS records are operational metadata on Microsoft-managed infrastructure; no CMK encryption capability is exposed on the zone resource.",
        "expected_value": "N/A — CMK not supported on DNS Zone resource",
        "evidence_url": _EVIDENCE,
    }


def check_dp6_key_mgmt(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-6",
        "feature": "Key Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": "Azure DNS Zone stores no secrets, keys, or sensitive credentials. No Key Vault integration is applicable to the zone resource itself.",
        "expected_value": "N/A — DNS Zone holds no secrets; KV not applicable",
        "evidence_url": _EVIDENCE,
    }


def check_dp7_cert_kv(credential, subscription_id: str, resource_group: str | None, zone_name: str | None) -> dict:
    return {
        "resource": zone_name or "all",
        "control_id": "DP-7",
        "feature": "Certificate Management in Azure Key Vault",
        "status": "UNKNOWN",
        "actual_value": (
            "Azure DNS Zone manages DNS records, not TLS certificates. "
            "CAA records can enforce which CAs may issue certificates for a domain, "
            "but the zone resource itself uses no certificates and has no KV certificate integration. "
            "KV certificate management not applicable."
        ),
        "expected_value": "N/A — DNS Zone manages DNS records, not TLS certificates; KV cert management not applicable",
        "evidence_url": _EVIDENCE,
    }

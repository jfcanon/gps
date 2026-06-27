"""
Data Protection checks for Azure Logic Apps (MCSB v3).

DP-3: Static PASS (HTTPS enforced).
DP-4: Static PASS (platform-managed at rest).
DP-5: CMK available for ISE only — not ARM-readable on workflow → UNKNOWN.
DP-6: Key management via KV → UNKNOWN (ISE/Standard only).
DP-7: Cert management via KV → UNKNOWN (linked service level).

Read-only. Zero ARM writes.
"""


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3", "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure Logic Apps enforces HTTPS for all trigger and action endpoints. HTTP triggers can be disabled via access policies.",
            "expected_value": "HTTPS enforced (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/security-baseline#dp-3-encrypt-sensitive-data-in-transit"}


def check_dp4_platform_keys(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-4", "feature": "Encrypt Data at Rest with Platform-Managed Keys",
            "status": "PASS",
            "actual_value": "Logic Apps workflow definitions and run history are encrypted at rest with Microsoft-managed keys by default.",
            "expected_value": "Microsoft-managed encryption (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/security-baseline#dp-4-enable-data-at-rest-encryption-by-default"}


def check_dp5_cmk(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-5", "feature": "Encrypt Data at Rest with Customer-Managed Key",
            "status": "UNKNOWN",
            "actual_value": "CMK encryption is available for Logic Apps ISE (Integration Service Environment) via the ISE resource, not the workflow ARM resource. Consumption plan does not support CMK.",
            "expected_value": "CMK enabled on ISE resource for Consumption Logic Apps in ISE",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/customer-managed-keys-integration-service-environment"}


def check_dp6_key_mgmt(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-6", "feature": "Manage Cryptographic Keys using Key Management Service",
            "status": "UNKNOWN",
            "actual_value": "Key Vault is used for CMK in ISE and for connector credentials in Standard Logic Apps. Key configuration is at ISE or App Service level, not readable per workflow ARM resource.",
            "expected_value": "CMK via Key Vault on ISE resource",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/customer-managed-keys-integration-service-environment"}


def check_dp7_cert_kv(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-7", "feature": "Certificate Management in Azure Key Vault",
            "status": "UNKNOWN",
            "actual_value": "Logic Apps connectors referencing Key Vault for secrets/certs is configured at the connector/connection level in workflows, not ARM-readable per workflow resource.",
            "expected_value": "Logic App connections reference Key Vault for credentials (not inline secrets)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/logic-apps/store-credentials-azure-key-vault"}

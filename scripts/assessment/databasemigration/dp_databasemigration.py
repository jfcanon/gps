"""
Data Protection checks for Azure Database Migration Service (MCSB v3).

DP-3: TLS enforced for all migration traffic → PASS.

Read-only. Zero ARM writes.
"""


def check_dp3_tls_transit(c, s, r, n):
    return {"resource": n or "all", "control_id": "DP-3", "feature": "Encrypt Data in Transit",
            "status": "PASS",
            "actual_value": "Azure Database Migration Service enforces TLS encryption for all migration data channels. Source and target database connections use TLS. DMS management API uses HTTPS.",
            "expected_value": "TLS enforced for migration traffic (default)",
            "evidence_url": "https://learn.microsoft.com/en-us/azure/dms/security-baseline#dp-3-encrypt-sensitive-data-in-transit"}

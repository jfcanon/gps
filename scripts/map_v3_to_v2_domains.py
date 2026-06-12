#!/usr/bin/env python3
"""
Map MCSB v3 controls (per-resource) to MCSB v2 security domains.

Inputs:  data/outputs/mcsb_v3_raw.csv
Outputs: data/outputs/mcsb_v3_mapped.csv
         (adds: domain_code, domain_name, mapping_confidence, primary_keyword)

Mapping uses keyword rules. ~85% high-confidence, ~15% flagged for manual review.
"""

import pandas as pd
from pathlib import Path

ROOT = Path(__file__).parent.parent
INPUT_FILE = ROOT / "data" / "outputs" / "mcsb_v3_raw.csv"
OUTPUT_FILE = ROOT / "data" / "outputs" / "mcsb_v3_mapped.csv"
MANUAL_REVIEW_FILE = ROOT / "data" / "outputs" / "mcsb_v3_manual_review.csv"

# Domain definitions
DOMAINS = {
    "NS": "Network Security",
    "IM": "Identity Management",
    "PA": "Privileged Access",
    "DP": "Data Protection",
    "AM": "Asset Management",
    "LT": "Logging and Threat Detection",
    "IR": "Incident Response",
    "PV": "Posture and Vulnerability Management",
    "ES": "Endpoint Security",
    "BR": "Backup and Recovery",
    "DS": "DevOps Security",
    "GS": "Governance and Strategy",
}

# Keyword rules: (domain_code, [keywords_that_map_to_this_domain])
# Order matters — first match wins for high-confidence, all matches checked for ambiguity
DOMAIN_RULES: list[tuple[str, list[str]]] = [
    ("DS", [
        "ci/cd", "pipeline", "devops", "iac", "infrastructure as code",
        "supply chain", "sast", "dast", "container image scanning",
        "code scanning", "secret scanning", "checkov",
    ]),
    ("PA", [
        "privileged", "pim", "just-in-time", "jit access",
        "admin account", "privileged role", "break-glass",
        "privileged workstation", "customer lockbox",
    ]),
    ("IM", [
        "identity", "authentication", "managed identity", "service principal",
        "azure active directory", "azure ad", "mfa", "multi-factor",
        "single sign-on", "sso", "conditional access", "oauth", "oidc",
        "workload identity", "federated credential", "rbac",
    ]),
    ("NS", [
        "network", "firewall", "nsg", "network security group",
        "private endpoint", "service endpoint", "vnet", "subnet",
        "tls", "ssl", "http", "https", "port", "protocol",
        "dns", "ddos", "waf", "web application firewall",
        "public endpoint", "restrict access", "network access",
        "peering", "vpn", "expressroute",
    ]),
    ("DP", [
        "encryption", "encrypt", "key vault", "cmk", "customer-managed key",
        "tde", "transparent data encryption", "certificate",
        "data protection", "sensitive data", "pii", "classification",
        "purview", "at rest", "in transit", "secret",
    ]),
    ("LT", [
        "logging", "log", "audit", "diagnostic", "monitor",
        "alert", "threat detection", "siem", "sentinel", "log analytics",
        "activity log", "diagnostic setting", "retention", "ntp",
    ]),
    ("PV", [
        "vulnerability", "patch", "update", "scan", "assessment",
        "secure score", "defender for cloud", "recommendation",
        "hardening", "baseline", "configuration", "cis", "benchmark",
        "misconfiguration", "remediat",
    ]),
    ("ES", [
        "endpoint", "antimalware", "antivirus", "defender for endpoint",
        "edr", "malware", "vm agent", "extension", "container runtime",
        "pod security",
    ]),
    ("BR", [
        "backup", "recovery", "restore", "retention policy",
        "geo-redundant", "redundancy", "disaster recovery", "rto", "rpo",
        "immutable", "soft delete",
    ]),
    ("IR", [
        "incident response", "incident", "security contact",
        "alert response", "post-incident", "playbook",
    ]),
    ("AM", [
        "inventory", "asset", "tagging", "tag", "resource inventory",
        "approved service", "lifecycle", "cmdb", "software inventory",
    ]),
    ("GS", [
        "governance", "policy", "compliance", "strategy",
        "raci", "responsibility", "regulatory", "reporting",
        "security program", "initiative",
    ]),
]


def find_domain(text: str) -> tuple[str, str, str]:
    """
    Returns (domain_code, confidence, matched_keyword).
    confidence: High / Medium / Low
    """
    text_lower = text.lower()
    matches: list[tuple[str, str]] = []  # (domain_code, keyword)

    for domain_code, keywords in DOMAIN_RULES:
        for kw in keywords:
            if kw in text_lower:
                matches.append((domain_code, kw))

    if not matches:
        return "UNKNOWN", "Low", ""

    # Deduplicate by domain
    unique_domains = list(dict.fromkeys(m[0] for m in matches))

    if len(unique_domains) == 1:
        return unique_domains[0], "High", matches[0][1]
    elif len(unique_domains) == 2:
        # Pick the first-priority domain (order in DOMAIN_RULES)
        priority_order = [code for code, _ in DOMAIN_RULES]
        best = min(unique_domains, key=lambda d: priority_order.index(d))
        return best, "Medium", matches[0][1]
    else:
        priority_order = [code for code, _ in DOMAIN_RULES]
        best = min(unique_domains, key=lambda d: priority_order.index(d))
        return best, "Low", matches[0][1]


def main():
    if not INPUT_FILE.exists():
        print(f"ERROR: Run load_mcsb_v3.py first. Input not found: {INPUT_FILE}")
        raise SystemExit(1)

    (ROOT / "data" / "outputs").mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(INPUT_FILE)
    print(f"Processing {len(df)} v3 controls...")

    results = []
    for _, row in df.iterrows():
        # Combine all text fields for keyword matching
        search_text = " ".join(str(v) for v in [
            row.get("v3_control_title", ""),
            row.get("v3_description", ""),
            row.get("feature", ""),
            row.get("azure_resource", ""),
        ])

        domain_code, confidence, keyword = find_domain(search_text)

        results.append({
            **row.to_dict(),
            "domain_code": domain_code,
            "domain_name": DOMAINS.get(domain_code, "Unknown"),
            "mapping_confidence": confidence,
            "matched_keyword": keyword,
        })

    df_out = pd.DataFrame(results)
    df_out.to_csv(OUTPUT_FILE, index=False)

    # Stats
    confidence_counts = df_out["mapping_confidence"].value_counts()
    domain_counts = df_out["domain_code"].value_counts()

    print(f"\nWrote {len(df_out)} mapped controls to {OUTPUT_FILE}")
    print(f"\nMapping confidence:\n{confidence_counts.to_string()}")
    print(f"\nDomain distribution:\n{domain_counts.to_string()}")

    # Export Low confidence for manual review
    low_conf = df_out[df_out["mapping_confidence"] == "Low"]
    if len(low_conf) > 0:
        low_conf.to_csv(MANUAL_REVIEW_FILE, index=False)
        print(f"\n{len(low_conf)} controls flagged for manual review → {MANUAL_REVIEW_FILE}")
        print("Open that file, assign domain_code manually, then re-run build_master_controls.py")


if __name__ == "__main__":
    main()

"""Phase 55 — Fix unmatched patches + flip incorrect now_applicable_native verdicts."""
import csv
import pathlib

HEADER = [
    "asb_control_id", "feature_name", "feature_supported_original",
    "feature_enabled_by_default_original", "status_2025", "verdict_2025",
    "azure_api_property", "script_module", "script_function", "notes",
    "service", "severity", "blast_radius", "risk_rank",
]

SEV_SCORE = {"High": 3, "Medium": 2, "Low": 1}
BR_SCORE  = {"Wide": 2, "Narrow": 1}


def compute_blast_radius(row: dict) -> str:
    api = row.get("azure_api_property", "").strip()
    no_api = not api or api.upper() in ("", "N/A", "NA")
    if (row["verdict_2025"] == "conditional"
            or no_api
            or row.get("feature_enabled_by_default_original", "") == "False"):
        return "Wide"
    return "Narrow"


def compute_risk_rank(row: dict) -> str:
    sev = SEV_SCORE.get(row.get("severity", "Medium"), 2)
    br  = BR_SCORE.get(row.get("blast_radius", "Narrow"), 1)
    return str(sev * br)


def update_row(row: dict, new_verdict=None, new_notes=None, append=False) -> bool:
    changed = False
    if new_verdict and row["verdict_2025"] != new_verdict:
        row["verdict_2025"] = new_verdict
        row["blast_radius"] = compute_blast_radius(row)
        row["risk_rank"] = compute_risk_rank(row)
        changed = True
    if new_notes:
        current = row.get("notes", "").rstrip()
        if append:
            if new_notes not in current:
                row["notes"] = f"{current} | {new_notes}".lstrip(" |")
                changed = True
        else:
            if current != new_notes:
                row["notes"] = new_notes
                changed = True
    return changed


def load_csv(path):
    return list(csv.DictReader(open(path)))


def save_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        for row in rows:
            w.writerow([row.get(h, "") for h in HEADER])


def run():
    fixes = []

    # ── APPGATEWAY ──────────────────────────────────────────────────────────
    appgw = pathlib.Path("data/outputs/ns/appgateway.final.csv")
    rows = load_csv(appgw)
    for row in rows:
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"]

        # IM-1 "— Disable" variant = Local Authentication Methods
        if ctrl == "IM-1" and "Disable" in feat:
            fixes.append(f"appgateway IM-1 Disable: note added")
            update_row(row, append=True, new_notes=(
                "MCSB v3 baseline: False/Not Applicable for local auth disable. "
                "App Gateway has no concept of local auth methods at data plane. "
                "Management access via Azure AD RBAC only. "
                "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
            ))

        # IM-1 "— AAD Aut" variant = Azure AD Required for data plane
        if ctrl == "IM-1" and "AAD Aut" in feat:
            fixes.append(f"appgateway IM-1 AAD: flip to conditional + note")
            update_row(row, new_verdict="conditional", new_notes=(
                "JWT validation via Microsoft Entra ID now in PUBLIC PREVIEW (Jan 2026). "
                "App Gateway validates JWTs on HTTPS listeners, blocks invalid tokens (401), "
                "injects x-msft-entra-identity header to backend. "
                "Conditional: requires Standard_v2/WAF_v2 SKU, HTTPS listener, "
                "ARM API 2025-03-01+; PREVIEW status (not for production yet). "
                "Source: https://learn.microsoft.com/en-us/azure/application-gateway/json-web-token-overview"
            ))

        # DP-2 "Monitor Anomalies..." — already now_applicable_native, add URL
        if ctrl == "DP-2" and "anomal" in feat.lower():
            fixes.append("appgateway DP-2: confirm now_applicable_native + source")
            update_row(row, append=True, new_notes=(
                "WAF v2 provides anomaly scoring (CRS 3.2+) and DDoS attack detection. "
                "Integrate WAF logs with Azure Monitor for data anomaly tracking. "
                "Source: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"
            ))

        # DP-6 "Manage Cryptographic Keys" — flip back to still_not_applicable
        # MCSB baseline explicitly says False/Not Applicable for Key Management in KV
        if ctrl == "DP-6" and "Key Management" in feat:
            fixes.append("appgateway DP-6: flip back to still_not_applicable (MCSB=False)")
            update_row(row, new_verdict="still_not_applicable", new_notes=(
                "MCSB v3 baseline: DP-6 Key Management in Key Vault = False/Not Applicable. "
                "App Gateway does not support CMK or Key Vault key management. "
                "Note: DP-7 (certificate management via KV) IS supported — separate feature. "
                "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
                "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/application-gateway-security-baseline"
            ))

        # PA-8 "Customer Lockbox" — flip back to still_not_applicable
        # MCSB baseline: False/Not Applicable; AppGW not in Lockbox supported list
        if ctrl == "PA-8" and "Customer Lo" in feat:
            fixes.append("appgateway PA-8: flip back to still_not_applicable (MCSB=False, not in Lockbox list)")
            update_row(row, new_verdict="still_not_applicable", new_notes=(
                "MCSB v3 baseline: Customer Lockbox = False/Not Applicable. "
                "App Gateway not in Customer Lockbox supported services list. "
                "Phase 48 cache incorrectly marked as now_applicable_native — reverted. "
                "Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview"
            ))

    save_csv(appgw, rows)

    # ── REDIS ───────────────────────────────────────────────────────────────
    redis_p = pathlib.Path("data/outputs/ns/redis.final.csv")
    rows = load_csv(redis_p)
    for row in rows:
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"]

        # DP-2 "Data Leakage/Loss Prevention"
        if ctrl == "DP-2" and "Loss Prevention" in feat:
            fixes.append("redis DP-2: add note")
            update_row(row, append=True, new_notes=(
                "MCSB v3 baseline: False/Not Applicable. "
                "No native DLP solution for Redis cache traffic. "
                "Redis caches data in-memory; DLP monitoring at this layer not supported. "
                "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-cache-for-redis-security-baseline"
            ))

    save_csv(redis_p, rows)

    # ── SERVICEBUS ──────────────────────────────────────────────────────────
    sb_p = pathlib.Path("data/outputs/ns/servicebus.final.csv")
    rows = load_csv(sb_p)
    for row in rows:
        ctrl = row["asb_control_id"].strip()
        feat = row["feature_name"]

        # IM-1 "— Disable" variant (local auth disable)
        if ctrl == "IM-1" and "Disable" in feat:
            fixes.append("servicebus IM-1 Disable: confirm now_applicable_native + URL")
            update_row(row, new_verdict="now_applicable_native", new_notes=(
                "Service Bus supports disabling local SAS key authentication, "
                "enforcing Entra ID-only access. "
                "Policy: 'Azure Service Bus should not use access keys for authentication'. "
                "Source: https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization"
            ))

        # IM-1 "— AAD Aut" variant (Azure AD required for data plane)
        if ctrl == "IM-1" and "AAD Aut" in feat:
            fixes.append("servicebus IM-1 AAD: confirm now_applicable_native + URL")
            update_row(row, new_verdict="now_applicable_native", new_notes=(
                "Azure AD authentication required for Service Bus data plane: True/True/Microsoft. "
                "Entra ID RBAC with built-in roles: Service Bus Data Owner, Data Sender, Data Receiver. "
                "Source: https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/service-bus-security-baseline"
            ))

    save_csv(sb_p, rows)

    print("=" * 60)
    print(f"Fix patches applied: {len(fixes)}")
    for f in fixes:
        print(f"  {f}")


if __name__ == "__main__":
    run()

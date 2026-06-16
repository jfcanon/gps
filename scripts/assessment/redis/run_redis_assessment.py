#!/usr/bin/env python3
"""
Azure Cache for Redis — Compliance Assessment Runner

Runs read-only MCSB v3 control checks against Redis instances.
Zero writes to Azure. Auth via DefaultAzureCredential.
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CHECK REGISTRY
# Part 1 will register check functions here.
# Each entry: "control_id:feature_slug" -> callable
# Signature: fn(credential, subscription_id, resource_group, redis_name) -> dict
# Return dict keys: resource, control_id, feature, status, actual_value,
#                   expected_value, evidence_url
# ---------------------------------------------------------------------------
CHECK_REGISTRY: dict[str, callable] = {
    # NS domain — ns_redis.py
    # "NS-1:nsg_support": ns_redis.check_ns1_nsg,
    # "NS-1:vnet_integration": ns_redis.check_ns1_vnet,
    # "NS-2:private_link": ns_redis.check_ns2_private_link,
    # "NS-2:disable_public_access": ns_redis.check_ns2_public_access,

    # DP domain — dp_redis.py
    # "DP-2:dlp": dp_redis.check_dp2_dlp,
    # "DP-3:transit_encryption": dp_redis.check_dp3_tls,
    # "DP-4:platform_keys": dp_redis.check_dp4_platform_keys,
    # "DP-5:cmk": dp_redis.check_dp5_cmk,

    # IM domain — im_redis.py
    # "IM-1:local_auth": im_redis.check_im1_local_auth,
    # "IM-8:keyvault": im_redis.check_im8_keyvault,

    # LT domain — lt_redis.py
    # "LT-4:resource_logs": lt_redis.check_lt4_resource_logs,

    # PA domain — pa_redis.py
    # "PA-1:local_admin": pa_redis.check_pa1_local_admin,

    # AM domain — am_redis.py
    # "AM-2:policy_support": am_redis.check_am2_policy,

    # BR domain — br_redis.py
    # "BR-1:backup": br_redis.check_br1_backup,

    # ES domain — es_redis.py
    # (ES controls are not_applicable for Redis — see es_redis.py for rationale)

    # PV domain — pv_redis.py
    # (PV controls are not_applicable for Redis PaaS — see pv_redis.py)
}


def run_checks(credential, subscription_id: str, resource_group: str | None, redis_name: str | None) -> list[dict]:
    results = []
    for key, check_fn in CHECK_REGISTRY.items():
        log.info(f"Running check: {key}")
        try:
            result = check_fn(credential, subscription_id, resource_group, redis_name)
            results.append(result)
        except Exception as e:
            control_id, feature = key.split(":", 1) if ":" in key else (key, key)
            log.error(f"Check {key} failed: {e}")
            results.append({
                "resource": redis_name or "UNKNOWN",
                "control_id": control_id,
                "feature": feature,
                "status": "UNKNOWN",
                "actual_value": None,
                "expected_value": None,
                "evidence_url": None,
                "error": str(e)
            })
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Run MCSB v3 compliance checks for Azure Cache for Redis'
    )
    parser.add_argument('--subscription-id', required=True, help='Azure subscription ID')
    parser.add_argument('--resource-group', default=None, help='Scope to specific resource group')
    parser.add_argument('--redis-name', default=None, help='Scope to specific Redis instance name')
    parser.add_argument('--output-dir', default='data/outputs/assessment_results',
                        help='Output directory for results (default: %(default)s)')
    args = parser.parse_args()

    if not CHECK_REGISTRY:
        log.warning("CHECK_REGISTRY is empty — no checks registered yet. Run after Phase 43 Part 1.")
        sys.exit(0)

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except ImportError:
        log.error("azure-identity not installed. Run: pip install azure-identity azure-mgmt-redis")
        sys.exit(1)

    log.info(f"Running {len(CHECK_REGISTRY)} checks for subscription {args.subscription_id}")
    results = run_checks(credential, args.subscription_id, args.resource_group, args.redis_name)

    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out_file = os.path.join(args.output_dir, f"redis_{args.subscription_id}_{timestamp}.json")

    summary = {
        "service": "azure-cache-for-redis",
        "subscription_id": args.subscription_id,
        "resource_group": args.resource_group,
        "redis_name": args.redis_name,
        "run_timestamp": timestamp,
        "total_checks": len(results),
        "pass": sum(1 for r in results if r.get("status") == "PASS"),
        "fail": sum(1 for r in results if r.get("status") == "FAIL"),
        "unknown": sum(1 for r in results if r.get("status") == "UNKNOWN"),
        "results": results
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    log.info(f"Results written to {out_file}")
    log.info(f"PASS={summary['pass']} FAIL={summary['fail']} UNKNOWN={summary['unknown']}")


if __name__ == "__main__":
    main()

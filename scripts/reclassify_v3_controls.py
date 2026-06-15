"""
reclassify_v3_controls.py
-------------------------
Phase 37 (step 2): Qwen3-driven reclassification of v3 controls.

Step A: For each unique control ID (~34), call Qwen3 to determine:
  - applicability in 2025 (customer / not_applicable / microsoft_managed)
  - newly_applicable (was N/A, now feasible with 2025 tech)
  - automation_class (script_simple / script_medium / manual_only / not_applicable)
  - confidence + rationale

Step B: Propagate judgments to full 4,157-row CSV.
  Column strategy: keep "applicability" name (downstream scripts depend on it),
  add "applicability_original" (Excel-based Phase 35 value) for audit trail.

Inputs:
  data/outputs/v3_unique_controls.csv         (34 rows from extract_unique_controls.py)
  data/outputs/v3_service_controls_reviewed.csv

Outputs:
  data/outputs/v3_control_judgments.json      (34 Qwen3 verdicts)
  data/outputs/v3_service_controls_reclassified.csv

Usage:
  python3 reclassify_v3_controls.py [--unique PATH] [--reviewed PATH] [--judgments PATH] [--out PATH]
  python3 reclassify_v3_controls.py --skip-qwen  # Step B only (reuse existing judgments)
"""

import csv
import json
import re
import time
import argparse
import subprocess
from pathlib import Path

ROOT          = Path(__file__).parent.parent
UNIQUE_CSV    = ROOT / "data" / "outputs" / "v3_unique_controls.csv"
REVIEWED_CSV  = ROOT / "data" / "outputs" / "v3_service_controls_reviewed.csv"
JUDGMENTS_JSON = ROOT / "data" / "outputs" / "v3_control_judgments.json"
OUT_CSV       = ROOT / "data" / "outputs" / "v3_service_controls_reclassified.csv"
QWEN_CMD_DIR  = "/Users/nahuelavalos/Repo/claude/workspaces/kimi/demo-local"
PROMPT_TMP    = "/tmp/qwen_prompt.txt"

VALID_APPLICABILITY  = {"customer", "not_applicable", "microsoft_managed"}
VALID_AUTO_CLASS     = {"script_simple", "script_medium", "manual_only", "not_applicable"}
VALID_CONFIDENCE     = {"high", "medium", "low"}

PROMPT_TEMPLATE = """You are a cloud security engineer analyzing Microsoft Cloud Security Benchmark (MCSB) v3 controls for Azure.

Control ID: {control_id}
Domain: {domain}
Title: {title}
Guidance: {guidance}
Current Excel classification: {dist} across {service_count} Azure services

Answer ONLY with a JSON object (no markdown, no extra text, no <think> tags):
{{
  "control_id": "{control_id}",
  "applicability_2025": "customer|not_applicable|microsoft_managed",
  "newly_applicable": true|false,
  "automation_class": "script_simple|script_medium|manual_only|not_applicable",
  "confidence": "high|medium|low",
  "rationale": "<one sentence max, no quotes inside>"
}}

Rules for applicability_2025:
- "customer" = customer can and should implement in 2025 (native Azure feature OR mature third-party tool: ClamAV, Defender for Cloud, Sentinel, CrowdStrike, Qualys)
- "not_applicable" = genuinely not applicable even with 2025 tech (e.g. EDR on pure PaaS with no compute layer where third-party tools cannot run)
- "microsoft_managed" = Microsoft fully manages this, no customer action possible

Rules for newly_applicable:
- true = control was N/A in Excel BUT a native Azure feature OR mature third-party integration makes it feasible in 2025
- false = original applicability still correct

Rules for automation_class:
- script_simple = az cli / REST API / PowerShell reads current compliance state in <10 lines
- script_medium = compliance check + remediation needs 10-50 lines, multi-step, fully automatable
- manual_only = no Azure API exposes this state; requires human review of docs, architecture, or interviews
- not_applicable = control does not apply, skip

Consider: Microsoft Defender for Cloud, Azure Policy, Azure Monitor, Defender for Endpoint, Defender for Storage, Microsoft Sentinel, az security CLI, Graph API, ARM REST, third-party tools (CrowdStrike, Broadcom CWP, ClamAV, Qualys, Tenable) for compute-adjacent services."""


def _call_qwen3(prompt: str) -> str:
    Path(PROMPT_TMP).write_text(prompt, encoding="utf-8")
    result = subprocess.run(
        ["bash", "-c",
         f'cd {QWEN_CMD_DIR} && AI_PROVIDER=local uv run python main.py "$(cat {PROMPT_TMP})"'],
        capture_output=True, text=True, timeout=200,
    )
    return result.stdout


def _extract_json(text: str) -> dict | None:
    # Strip <think>...</think> blocks first
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Find first {...} block
    match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return None


def _validate_judgment(j: dict, control_id: str) -> dict:
    j["control_id"] = control_id  # always trust input, not Qwen3 echo
    if j.get("applicability_2025") not in VALID_APPLICABILITY:
        j["applicability_2025"] = "customer"
    if j.get("automation_class") not in VALID_AUTO_CLASS:
        j["automation_class"] = "manual_only"
    if j.get("confidence") not in VALID_CONFIDENCE:
        j["confidence"] = "low"
    # newly_applicable: coerce to bool
    na = j.get("newly_applicable", False)
    if isinstance(na, str):
        na = na.lower() in ("true", "1", "yes")
    j["newly_applicable"] = bool(na)
    # Strip quotes from rationale that could break CSV
    j["rationale"] = str(j.get("rationale", "")).replace('"', "'")[:200]
    return j


def _fallback_judgment(control_id: str, reason: str) -> dict:
    return {
        "control_id":        control_id,
        "applicability_2025": "unknown",
        "newly_applicable":  False,
        "automation_class":  "manual_only",
        "confidence":        "low",
        "rationale":         reason,
    }


def step_a_qwen3_loop(unique_path: str, judgments_path: str) -> list[dict]:
    with open(unique_path, newline="", encoding="utf-8") as f:
        controls = list(csv.DictReader(f))

    # Resume: load existing judgments if file exists
    existing: dict[str, dict] = {}
    jp = Path(judgments_path)
    if jp.exists():
        try:
            existing = {j["control_id"]: j for j in json.loads(jp.read_text())}
            print(f"Resuming: {len(existing)} existing judgments found")
        except Exception:
            pass

    judgments: list[dict] = list(existing.values())

    for i, ctrl in enumerate(controls, 1):
        cid = ctrl["asb_control_id"]
        if cid in existing:
            print(f"  [{i:2d}/{len(controls)}] {cid:<8} — cached")
            continue

        prompt = PROMPT_TEMPLATE.format(
            control_id=cid,
            domain=ctrl["control_domain"],
            title=ctrl["asb_control_title"],
            guidance=ctrl["guidance"][:1500],
            dist=ctrl["current_auto_class_distribution"],
            service_count=ctrl["service_count"],
        )

        print(f"  [{i:2d}/{len(controls)}] {cid:<8} ", end="", flush=True)
        raw = _call_qwen3(prompt)
        j = _extract_json(raw)

        if j is None:
            # Retry with explicit JSON-only instruction
            retry_prompt = "Respond ONLY with a JSON object. No prose. No markdown.\n\n" + prompt
            raw2 = _call_qwen3(retry_prompt)
            j = _extract_json(raw2)

        if j is None:
            j = _fallback_judgment(cid, "parse_failed")
            print(f"PARSE_FAILED")
        else:
            j = _validate_judgment(j, cid)
            print(f"→ {j['applicability_2025']} / {j['automation_class']} ({j['confidence']})")

        judgments.append(j)
        # Persist after each call (resume-safe)
        jp.write_text(json.dumps(judgments, indent=2), encoding="utf-8")
        time.sleep(0.5)

    print(f"\n→ {jp}  ({len(judgments)} judgments)")
    return judgments


def step_b_propagate(reviewed_path: str, judgments: list[dict], out_path: str) -> None:
    j_map = {j["control_id"]: j for j in judgments}

    with open(reviewed_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    matched = 0
    newly_flipped = 0

    for row in rows:
        cid = row.get("asb_control_id", "")
        row["applicability_original"] = row.get("applicability", "")

        if cid in j_map:
            j = j_map[cid]
            row["applicability"]              = j["applicability_2025"]
            row["automation_class"]           = j["automation_class"]
            row["newly_applicable"]           = str(j["newly_applicable"])
            row["reclassification_confidence"] = j["confidence"]
            row["reclassification_rationale"] = j["rationale"]
            matched += 1
            if j["newly_applicable"]:
                newly_flipped += 1
        else:
            row["reclassification_confidence"] = "none"
            row["reclassification_rationale"]  = "no_judgment"

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    from collections import Counter
    old_dist = Counter(r["applicability_original"] for r in rows)
    new_dist = Counter(r["applicability"] for r in rows)
    old_auto = Counter(r.get("automation_class", "") for r in rows)

    print(f"\nReclassified {matched} rows from {len(j_map)} judgments")
    print(f"Newly applicable: {newly_flipped} rows flipped")
    print(f"\nApplicability delta:")
    print(f"  old: {dict(old_dist)}")
    print(f"  new: {dict(new_dist)}")

    cust_rows = [r for r in rows if r["applicability"] == "customer"]
    print(f"\nCustomer rows automation_class (new): {dict(Counter(r['automation_class'] for r in cust_rows))}")
    print(f"\n→ {out}")


def main(unique_path: str, reviewed_path: str, judgments_path: str, out_path: str, skip_qwen: bool) -> None:
    if not skip_qwen:
        print("=== Step A: Qwen3 reclassification loop ===")
        judgments = step_a_qwen3_loop(unique_path, judgments_path)
    else:
        print("=== Step A: Skipped (--skip-qwen), loading existing judgments ===")
        with open(judgments_path, encoding="utf-8") as f:
            judgments = json.load(f)
        print(f"Loaded {len(judgments)} existing judgments from {judgments_path}")

    print("\n=== Step B: Propagate to full CSV ===")
    step_b_propagate(reviewed_path, judgments, out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--unique",    default=str(UNIQUE_CSV))
    parser.add_argument("--reviewed",  default=str(REVIEWED_CSV))
    parser.add_argument("--judgments", default=str(JUDGMENTS_JSON))
    parser.add_argument("--out",       default=str(OUT_CSV))
    parser.add_argument("--skip-qwen", action="store_true",
                        help="Skip Qwen3 calls, use existing judgments JSON")
    args = parser.parse_args()
    main(args.unique, args.reviewed, args.judgments, args.out, args.skip_qwen)

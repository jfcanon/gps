"""
import_assessment_tasks_to_ado.py
----------------------------------
Reads a *_rechecked_controls.csv (10-column Redis schema) and creates ADO Tasks
as children of matching User Stories — one Task per assessment control check row.

Prerequisites:
  1. export ADO_PAT=<your-personal-access-token>
  2. Edit ado_config.py: ADO_ORG, ADO_PROJECT, AREA_PATH, ITERATION_PATH
  3. User Stories must already exist in ADO (created by import_to_ado.py)

Usage:
  python import_assessment_tasks_to_ado.py \
      --csv data/outputs/servicebus_rechecked_controls.csv \
      --service-name service-bus \
      [--dry-run]

PAT permissions required:
  Work Items (Read, Write, Manage)
"""

import sys
import base64
import csv
import json
import argparse
import time
import re
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
import ado_config as cfg

REQUIRED_COLUMNS = {
    "asb_control_id",
    "feature_name",
    "status_2025",
    "verdict_2025",
    "azure_api_property",
    "script_module",
    "script_function",
    "notes",
}


# ---------------------------------------------------------------------------
# ADO REST helpers (mirror import_to_ado.py)
# ---------------------------------------------------------------------------

def _auth_header() -> dict:
    token = base64.b64encode(f":{cfg.ADO_PAT}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _headers_patch() -> dict:
    return {**_auth_header(), "Content-Type": "application/json-patch+json"}


def _headers_get() -> dict:
    return {**_auth_header(), "Content-Type": "application/json"}


def _workitem_url(work_item_type: str) -> str:
    encoded_type = work_item_type.replace(" ", "%20")
    return (
        f"{cfg.ADO_ORG}/{cfg.ADO_PROJECT}/_apis/wit/workitems/"
        f"${encoded_type}?api-version={cfg.API_VERSION}"
    )


def _wiql_url() -> str:
    return (
        f"{cfg.ADO_ORG}/{cfg.ADO_PROJECT}/_apis/wit/wiql"
        f"?api-version={cfg.API_VERSION}"
    )


def _md_links_to_html(text: str) -> str:
    return re.sub(
        r'\[([^\]]+)\]\((https?://[^\)]+)\)',
        r'<a href="\2">\1</a>',
        text,
    )


# ---------------------------------------------------------------------------
# Work item lookup
# ---------------------------------------------------------------------------

def find_user_story(asb_control_id: str, service_name: str) -> int | None:
    """Find parent User Story by asb_control_id in title + service_name in tags."""
    esc_project = cfg.ADO_PROJECT.replace("'", "''")
    esc_control = asb_control_id.replace("'", "''")
    esc_service = service_name.replace("'", "''")
    query = {
        "query": (
            f"SELECT [System.Id] FROM WorkItems "
            f"WHERE [System.WorkItemType] = 'User Story' "
            f"AND [System.TeamProject] = '{esc_project}' "
            f"AND [System.Title] CONTAINS '{esc_control}' "
            f"AND [System.Tags] CONTAINS '{esc_service}'"
        )
    }
    resp = requests.post(_wiql_url(), headers=_headers_get(), json=query, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("workItems", [])
    if not items:
        return None
    if len(items) > 1:
        print(f"  [WARN] {len(items)} User Stories matched {asb_control_id}/{service_name} — using first match #{items[0]['id']}")
    return items[0]["id"]


def task_exists(title: str) -> int | None:
    """Return Task ID if a Task with this exact title already exists, else None."""
    esc_project = cfg.ADO_PROJECT.replace("'", "''")
    esc_title = title.replace("'", "''")
    query = {
        "query": (
            f"SELECT [System.Id] FROM WorkItems "
            f"WHERE [System.WorkItemType] = 'Task' "
            f"AND [System.TeamProject] = '{esc_project}' "
            f"AND [System.Title] = '{esc_title}'"
        )
    }
    resp = requests.post(_wiql_url(), headers=_headers_get(), json=query, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("workItems", [])
    return items[0]["id"] if items else None


# ---------------------------------------------------------------------------
# Task creation
# ---------------------------------------------------------------------------

def _build_task_ops(row: dict, service_name: str, parent_story_id: int) -> list[dict]:
    title = f"{row['asb_control_id']} — {row['feature_name']}"
    # AcceptanceCriteria is NOT valid on Task type — folded into Description.
    description = (
        f"<p><b>Property:</b> {_md_links_to_html(row['azure_api_property'])}</p>"
        f"<p>{_md_links_to_html(row['notes'])}</p>"
        f"<ul>"
        f"<li>Module: {row['script_module']}</li>"
        f"<li>Function: {row['script_function']}</li>"
        f"<li>Status 2025: {row['status_2025']}</li>"
        f"<li>Verdict 2025: {row['verdict_2025']}</li>"
        f"</ul>"
    )
    tags = f"{row['asb_control_id']}; {row['verdict_2025']}; assessment; {service_name}"
    parent_url = f"{cfg.ADO_ORG}/_apis/wit/workitems/{parent_story_id}"

    ops = [
        {"op": "add", "path": "/fields/System.Title",       "value": title},
        {"op": "add", "path": "/fields/System.Description", "value": description},
        {"op": "add", "path": "/fields/System.Tags",        "value": tags},
        {"op": "add", "path": "/relations/-", "value": {
            "rel": "System.LinkTypes.Hierarchy-Reverse",
            "url": parent_url,
            "attributes": {"comment": ""},
        }},
    ]
    if cfg.AREA_PATH:
        ops.append({"op": "add", "path": "/fields/System.AreaPath",      "value": cfg.AREA_PATH})
    if cfg.ITERATION_PATH:
        ops.append({"op": "add", "path": "/fields/System.IterationPath", "value": cfg.ITERATION_PATH})
    return ops


def create_task(row: dict, service_name: str, parent_story_id: int, _retry: bool = False) -> int:
    """Create ADO Task linked to parent User Story. Returns work item ID."""
    ops = _build_task_ops(row, service_name, parent_story_id)
    resp = requests.patch(
        _workitem_url("Task"),
        headers=_headers_patch(),
        data=json.dumps(ops),
        timeout=30,
    )
    if resp.status_code == 429 and not _retry:
        wait = int(resp.headers.get("Retry-After", 5))
        print(f"    [429] Rate limited — waiting {wait}s...")
        time.sleep(wait)
        return create_task(row, service_name, parent_story_id, _retry=True)
    if not resp.ok:
        print(f"    [DEBUG] HTTP {resp.status_code} — {resp.text[:600]}")
    resp.raise_for_status()
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Main import flow
# ---------------------------------------------------------------------------

def load_csv(csv_path: str) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def validate_csv_schema(rows: list[dict], csv_path: str) -> None:
    if not rows:
        print(f"[ERROR] CSV is empty: {csv_path}")
        sys.exit(1)
    actual_cols = set(rows[0].keys())
    missing = REQUIRED_COLUMNS - actual_cols
    if missing:
        print(f"[ERROR] CSV missing required columns: {sorted(missing)}")
        print(f"        Found columns: {sorted(actual_cols)}")
        sys.exit(1)


def run_import(csv_path: str, service_name: str, dry_run: bool, parent_id: int | None = None) -> None:
    # Always validate config — catch misconfig even in dry-run (fix vs import_to_ado.py which skips)
    errors = cfg.validate()
    if errors:
        if dry_run:
            for e in errors:
                print(f"[CONFIG WARN — dry-run] {e}")
        else:
            for e in errors:
                print(f"[CONFIG ERROR] {e}")
            sys.exit(1)

    if not Path(csv_path).exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        sys.exit(1)

    rows = load_csv(csv_path)
    validate_csv_schema(rows, csv_path)
    print(f"Loaded {len(rows)} rows from {csv_path}")
    print(f"Service: {service_name}")

    created = 0
    skipped = 0
    failed = 0
    no_parent = 0

    story_cache: dict[str, int | None] = {}

    print(f"\n── Creating Tasks ({len(rows)} total) ──────────────────────────")

    for i, row in enumerate(rows, 1):
        control_id = row["asb_control_id"]
        feature = row["feature_name"]
        title = f"{control_id} — {feature}"

        if dry_run:
            verdict = row["verdict_2025"]
            print(f"  [DRY-RUN] {i:3d}. Task: {title[:70]} [{verdict}]")
            continue

        # Find parent User Story — use direct ID if provided, else WIQL search
        if parent_id is not None:
            resolved_parent_id = parent_id
        else:
            cache_key = f"{control_id}::{service_name}"
            if cache_key not in story_cache:
                try:
                    story_cache[cache_key] = find_user_story(control_id, service_name)
                except requests.HTTPError as e:
                    print(f"  {i:3d}. [ERROR] Parent lookup for {control_id}: {e}")
                    story_cache[cache_key] = None
            resolved_parent_id = story_cache[cache_key]

        if resolved_parent_id is None:
            print(f"  {i:3d}. [NO PARENT] {title[:60]} — no User Story found for {control_id}/{service_name}")
            no_parent += 1
            continue

        # Idempotency check
        try:
            existing_id = task_exists(title)
            if existing_id:
                print(f"  {i:3d}. [SKIP] #{existing_id} already exists — {title[:55]}")
                skipped += 1
                time.sleep(0.1)
                continue
        except requests.HTTPError as e:
            print(f"  {i:3d}. [WARN] Idempotency check failed for '{title[:40]}': {e} — will attempt create")

        # Create task
        try:
            task_id = create_task(row, service_name or "", resolved_parent_id)
            print(f"  {i:3d}. Created #{task_id} — {title[:55]}")
            created += 1
            time.sleep(0.3)
        except requests.HTTPError as e:
            print(f"  {i:3d}. [ERROR] {title[:55]}: {e}")
            failed += 1

    print(f"\n{'DRY-RUN COMPLETE' if dry_run else 'IMPORT COMPLETE'}")
    if not dry_run:
        print(f"  Tasks created:   {created}")
        print(f"  Tasks skipped:   {skipped} (already exist)")
        print(f"  No parent found: {no_parent}")
        print(f"  Failed:          {failed}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Import MCSB assessment control checks as ADO Tasks under matching User Stories"
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Path to *_rechecked_controls.csv (10-col Redis schema)",
    )
    parser.add_argument(
        "--service-name",
        required=False,
        default=None,
        help="Service name tag for parent User Story WIQL lookup (e.g. service-bus, key-vault). Not needed when --parent-id is set.",
    )
    parser.add_argument(
        "--parent-id",
        type=int,
        default=None,
        help="ADO User Story work item ID. When set, skips WIQL search and links all tasks directly to this story.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview task list without creating ADO items",
    )
    args = parser.parse_args()
    if not args.parent_id and not args.service_name:
        parser.error("Provide --parent-id (preferred) or --service-name for parent User Story lookup")
    run_import(args.csv, args.service_name, args.dry_run, parent_id=args.parent_id)

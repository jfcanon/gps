"""
import_to_ado.py
---------------
Two-pass ADO import:
  Pass 1 — Create (or find) 12 Features, one per security domain.
  Pass 2 — Create ~160 User Stories, each linked to its parent Feature.

Prerequisites:
  1. Set environment variable:  export ADO_PAT=<your-personal-access-token>
  2. Edit ado_config.py:        ADO_ORG, ADO_PROJECT, AREA_PATH, ITERATION_PATH
  3. Run parse_stories.py first: python parse_stories.py

Usage:
  python import_to_ado.py [--csv PATH] [--dry-run]

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

# Import configuration from same directory
sys.path.insert(0, str(Path(__file__).parent))
import ado_config as cfg


# ---------------------------------------------------------------------------
# ADO REST helpers
# ---------------------------------------------------------------------------

def _auth_header() -> dict:
    """Build Basic auth header from PAT (no username needed)."""
    token = base64.b64encode(f":{cfg.ADO_PAT}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _headers_patch() -> dict:
    return {**_auth_header(), "Content-Type": "application/json-patch+json"}


def _headers_get() -> dict:
    return {**_auth_header(), "Content-Type": "application/json"}


def _workitem_url(work_item_type: str) -> str:
    """URL for creating a new work item of given type."""
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


# ---------------------------------------------------------------------------
# Markdown → minimal HTML conversion for ADO rich-text fields
# ---------------------------------------------------------------------------

def _md_links_to_html(text: str) -> str:
    """Convert [label](url) markdown links to <a href> tags."""
    return re.sub(
        r'\[([^\]]+)\]\((https?://[^\)]+)\)',
        r'<a href="\2">\1</a>',
        text,
    )


def desc_to_html(description: str) -> str:
    """Wrap plain description text in a paragraph with hyperlinks."""
    return f"<p>{_md_links_to_html(description)}</p>"


def ac_to_html(acceptance_criteria: str) -> str:
    """Convert newline-separated AC bullets into an HTML list."""
    bullets = [b.strip() for b in acceptance_criteria.split("\n") if b.strip()]
    items = "".join(f"<li>{_md_links_to_html(b)}</li>" for b in bullets)
    return f"<ul>{items}</ul>"


# ---------------------------------------------------------------------------
# Work item CRUD
# ---------------------------------------------------------------------------

def find_feature_by_title(title: str) -> int | None:
    """
    Search existing Features in the project by title.
    Returns work item ID if found, None otherwise.
    """
    # Escape single quotes in both values to prevent WIQL injection
    esc_project = cfg.ADO_PROJECT.replace("'", "''")
    esc_title   = title.replace("'", "''")
    query = {
        "query": (
            f"SELECT [System.Id] FROM WorkItems "
            f"WHERE [System.WorkItemType] = 'Feature' "
            f"AND [System.TeamProject] = '{esc_project}' "
            f"AND [System.Title] = '{esc_title}'"
        )
    }
    resp = requests.post(_wiql_url(), headers=_headers_get(), json=query, timeout=30)
    resp.raise_for_status()
    items = resp.json().get("workItems", [])
    return items[0]["id"] if items else None


def create_feature(feature_name: str) -> int:
    """Create an ADO Feature and return its work item ID."""
    ops = [
        {"op": "add", "path": "/fields/System.Title",         "value": feature_name},
        {"op": "add", "path": "/fields/System.Tags",          "value": "Security"},
    ]
    if cfg.AREA_PATH:
        ops.append({"op": "add", "path": "/fields/System.AreaPath",      "value": cfg.AREA_PATH})
    if cfg.ITERATION_PATH:
        ops.append({"op": "add", "path": "/fields/System.IterationPath", "value": cfg.ITERATION_PATH})

    resp = requests.patch(
        _workitem_url("Feature"),
        headers=_headers_patch(),
        data=json.dumps(ops),
        timeout=30,
    )
    resp.raise_for_status()
    work_item_id = resp.json()["id"]
    print(f"    Created Feature #{work_item_id}: {feature_name}")
    return work_item_id


def ensure_feature(feature_name: str, feature_cache: dict) -> int:
    """Return Feature ID, creating it only if it doesn't exist."""
    if feature_name in feature_cache:
        return feature_cache[feature_name]

    existing_id = find_feature_by_title(feature_name)
    if existing_id:
        print(f"    Found existing Feature #{existing_id}: {feature_name}")
        feature_cache[feature_name] = existing_id
        return existing_id

    new_id = create_feature(feature_name)
    feature_cache[feature_name] = new_id
    return new_id


def create_user_story(row: dict, parent_feature_id: int, _retry: bool = False) -> int:
    """
    Create an ADO User Story linked to a parent Feature.
    Returns the new work item ID. Retries once on HTTP 429.
    """
    parent_url = f"{cfg.ADO_ORG}/_apis/wit/workitems/{parent_feature_id}"

    ops = [
        {"op": "add", "path": "/fields/System.Title",       "value": row["story_title"]},
        {"op": "add", "path": "/fields/System.Description", "value": desc_to_html(row["description"])},
        {"op": "add", "path": "/fields/Microsoft.VSTS.Common.AcceptanceCriteria",
                                                             "value": ac_to_html(row["acceptance_criteria"])},
        {"op": "add", "path": "/fields/System.Tags",        "value": row["tags"]},
        # Link to parent Feature
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

    resp = requests.patch(
        _workitem_url("User Story"),
        headers=_headers_patch(),
        data=json.dumps(ops),
        timeout=30,
    )
    # Retry once on rate limit
    if resp.status_code == 429 and not _retry:
        wait = int(resp.headers.get("Retry-After", 5))
        print(f"    [429] Rate limited — waiting {wait}s then retrying...")
        time.sleep(wait)
        return create_user_story(row, parent_feature_id, _retry=True)
    resp.raise_for_status()
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Main import flow
# ---------------------------------------------------------------------------

def load_csv(csv_path: str) -> list[dict]:
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def run_import(csv_path: str, dry_run: bool) -> None:
    # Validate config before touching ADO
    errors = cfg.validate()
    if errors and not dry_run:
        for e in errors:
            print(f"[CONFIG ERROR] {e}")
        sys.exit(1)

    if not Path(csv_path).exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        print("        Run parse_stories.py first: python3 parse_stories.py")
        sys.exit(1)

    rows = load_csv(csv_path)
    print(f"Loaded {len(rows)} stories from {csv_path}")

    feature_cache: dict[str, int] = {}
    created_stories = 0
    failed_stories = 0

    # ── Pass 1: ensure all Features exist ────────────────────────────────────
    print("\n── Pass 1: Features ────────────────────────────────────────────")
    unique_features = {r["feature_name"] for r in rows}

    for feature_name in sorted(unique_features):
        if dry_run:
            print(f"  [DRY-RUN] Would create/find Feature: {feature_name}")
            feature_cache[feature_name] = 0
        else:
            try:
                ensure_feature(feature_name, feature_cache)
                time.sleep(0.2)   # gentle rate limit
            except requests.HTTPError as e:
                print(f"  [ERROR] Feature '{feature_name}': {e}")

    # ── Pass 2: create User Stories ──────────────────────────────────────────
    print(f"\n── Pass 2: User Stories ({len(rows)} total) ─────────────────────")

    for i, row in enumerate(rows, 1):
        feature_name = row["feature_name"]
        parent_id = feature_cache.get(feature_name, 0)

        if dry_run:
            print(f"  [DRY-RUN] {i:3d}. {row['domain']} {row['story_id']}: {row['story_title'][:60]}")
            continue

        try:
            story_id = create_user_story(row, parent_id)
            print(f"  {i:3d}. Created #{story_id} — {row['domain']} {row['story_id']}: {row['story_title'][:55]}")
            created_stories += 1
            time.sleep(0.3)   # stay well under ADO rate limits
        except requests.HTTPError as e:
            print(f"  {i:3d}. [ERROR] {row['domain']} {row['story_id']}: {e}")
            print(f"       Response: {e.response.text[:200] if e.response else 'no body'}")
            failed_stories += 1

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'DRY-RUN COMPLETE' if dry_run else 'IMPORT COMPLETE'}")
    if not dry_run:
        print(f"  Features:     {len(feature_cache)}")
        print(f"  Stories OK:   {created_stories}")
        print(f"  Stories FAIL: {failed_stories}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import MCSB v2 user stories into Azure DevOps")
    parser.add_argument("--csv",     default="ado_stories.csv", help="Input CSV (output of parse_stories.py)")
    parser.add_argument("--dry-run", action="store_true",        help="Preview without creating ADO items")
    args = parser.parse_args()
    run_import(args.csv, args.dry_run)

"""
ADO MVP Test — debug ADO connectivity and create 1 minimal Task.

Fill the 3 vars below. Run:
  python ado_mvp_test.py
"""

import base64, json, os
import requests

# ── Fill these ───────────────────────────────────────────────────────────────
PAT         = os.environ.get("ADO_PAT", "")          # export ADO_PAT=... before running
ORG         = "https://dev.azure.com/YOUR_ORG"       # NO trailing slash
PROJECT     = "YOUR_PROJECT"
PARENT_ID   = 12345                                   # the User Story ID to link task to
# ─────────────────────────────────────────────────────────────────────────────

def auth():
    token = base64.b64encode(f":{PAT}".encode()).decode()
    return {"Authorization": f"Basic {token}"}

def get(url):
    r = requests.get(url, headers={**auth(), "Content-Type": "application/json"}, timeout=15)
    return r

def patch(url, body):
    r = requests.patch(
        url,
        headers={**auth(), "Content-Type": "application/json-patch+json"},
        data=json.dumps(body),
        timeout=15,
    )
    return r

print(f"\n[1] Org URL:     {ORG}")
print(f"[1] Project:     {PROJECT}")
print(f"[1] Parent ID:   {PARENT_ID}")

# ── Step 2: verify project exists ────────────────────────────────────────────
project_url = f"{ORG}/_apis/projects/{PROJECT}?api-version=7.1"
print(f"\n[2] GET project: {project_url}")
r = get(project_url)
print(f"    HTTP {r.status_code}")
if r.ok:
    name = r.json().get("name", "?")
    print(f"    Project found: {name}")
else:
    print(f"    BODY: {r.text[:400]}")
    print("\n>>> Project lookup failed. Fix ORG/PROJECT/PAT first. Stop.")
    raise SystemExit(1)

# ── Step 3: verify parent work item exists ────────────────────────────────────
wi_url = f"{ORG}/_apis/wit/workitems/{PARENT_ID}?api-version=7.1"
print(f"\n[3] GET parent:  {wi_url}")
r = get(wi_url)
print(f"    HTTP {r.status_code}")
if r.ok:
    fields = r.json().get("fields", {})
    print(f"    Found: [{fields.get('System.WorkItemType')}] {fields.get('System.Title','?')[:60]}")
else:
    print(f"    BODY: {r.text[:400]}")
    print("\n>>> Parent work item not found. Check PARENT_ID. Stop.")
    raise SystemExit(1)

# ── Step 4: create 1 minimal Task ────────────────────────────────────────────
create_url = f"{ORG}/{PROJECT}/_apis/wit/workitems/$Task?api-version=7.1"
print(f"\n[4] POST task:   {create_url}")
parent_wi_url = f"{ORG}/_apis/wit/workitems/{PARENT_ID}"
ops = [
    {"op": "add", "path": "/fields/System.Title", "value": "[MVP-TEST] Delete me"},
    {"op": "add", "path": "/fields/System.Description", "value": "<p>MVP test — safe to delete.</p>"},
    {"op": "add", "path": "/relations/-", "value": {
        "rel": "System.LinkTypes.Hierarchy-Reverse",
        "url": parent_wi_url,
        "attributes": {"comment": ""},
    }},
]
r = patch(create_url, ops)
print(f"    HTTP {r.status_code}")
if r.ok:
    task_id = r.json()["id"]
    print(f"    Task created: #{task_id} — DELETE this test item in ADO.")
else:
    print(f"    BODY: {r.text[:600]}")
    print("\n>>> Task create failed. Share the BODY above for diagnosis.")

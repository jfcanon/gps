"""
parse_stories.py
----------------
Parses all 12 MCSB v2 domain user story .md files into a single CSV.

Input:  ../ado/user_stories/*.md  (12 files, ~160 stories)
Output: ado_stories.csv

CSV columns:
  domain, feature_name, story_id, story_title, resource, is_combined,
  description, acceptance_criteria, tags

Usage:
  python parse_stories.py [--out PATH]

The generated CSV is the input to import_to_ado.py.
"""

import re
import csv
import argparse
from pathlib import Path


# ---------------------------------------------------------------------------
# Domain metadata: file stem → (feature_name, domain_code)
# feature_name becomes the ADO Feature title.
# ---------------------------------------------------------------------------
DOMAIN_META = {
    "ns": ("[SEC-NS] Network Security — MCSB v2",                    "NS"),
    "im": ("[SEC-IM] Identity Management — MCSB v2",                  "IM"),
    "pa": ("[SEC-PA] Privileged Access — MCSB v2",                    "PA"),
    "dp": ("[SEC-DP] Data Protection — MCSB v2",                      "DP"),
    "am": ("[SEC-AM] Asset Management — MCSB v2",                     "AM"),
    "lt": ("[SEC-LT] Logging and Threat Detection — MCSB v2",         "LT"),
    "ir": ("[SEC-IR] Incident Response — MCSB v2",                    "IR"),
    "pv": ("[SEC-PV] Posture and Vulnerability Management — MCSB v2", "PV"),
    "es": ("[SEC-ES] Endpoint Security — MCSB v2",                    "ES"),
    "br": ("[SEC-BR] Backup and Recovery — MCSB v2",                  "BR"),
    "ds": ("[SEC-DS] DevOps Security — MCSB v2",                      "DS"),
    "gs": ("[SEC-GS] Governance and Strategy — MCSB v2",              "GS"),
}

# Regex: matches story title lines like  **[SEC-1] Title: Resource**
STORY_TITLE_RE = re.compile(r'^\*\*\[(SEC-\d+)\]\s+(.*?)\*\*\s*$')

CSV_FIELDS = [
    "domain", "feature_name", "story_id", "story_title",
    "resource", "is_combined", "description", "acceptance_criteria", "tags",
]


def parse_file(filepath: Path, feature_name: str, domain_code: str) -> list[dict]:
    """Parse one domain .md file and return a list of story dicts."""
    stories = []
    current: dict | None = None
    in_description = False
    in_ac = False
    desc_parts: list[str] = []
    ac_bullets: list[str] = []

    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    def _flush():
        """Finalise and store the current story."""
        if current:
            current["description"] = " ".join(desc_parts).strip()
            current["acceptance_criteria"] = "\n".join(ac_bullets)
            stories.append(current)

    for raw in lines:
        line = raw.rstrip("\n")

        # ── Story title ─────────────────────────────────────────────────────
        m = STORY_TITLE_RE.match(line)
        if m:
            _flush()
            # Reset state for new story
            in_description = False
            in_ac = False
            desc_parts = []
            ac_bullets = []

            story_id = m.group(1)           # "SEC-1"
            title_text = m.group(2).strip() # "Title: Resource" or "Title"

            # Split on first ": " to separate control title from resource name
            if ": " in title_text:
                ctrl, resource = title_text.split(": ", 1)
                is_combined = True
            else:
                ctrl = title_text
                resource = ""
                is_combined = False

            current = {
                "domain":        domain_code,
                "feature_name":  feature_name,
                "story_id":      story_id,
                "story_title":   f"[{story_id}] {title_text}",  # full ADO title
                "resource":      resource,
                "is_combined":   str(is_combined),
                "description":   "",
                "acceptance_criteria": "",
                "tags":          "Security",
            }
            continue

        if current is None:
            continue  # skip header/section lines before first story

        # ── Description line ────────────────────────────────────────────────
        if line.startswith("Description: "):
            in_description = True
            in_ac = False
            desc_parts = [line[len("Description: "):]]
            continue

        # ── Acceptance Criteria header ───────────────────────────────────────
        if line.strip() == "**Acceptance Criteria:**":
            in_description = False
            in_ac = True
            continue

        # ── Acceptance Criteria bullets ──────────────────────────────────────
        if in_ac and line.startswith("- "):
            ac_bullets.append(line[2:].strip())
            continue

        # ── Story separator ──────────────────────────────────────────────────
        if line.strip() == "---":
            _flush()
            current = None
            in_description = False
            in_ac = False
            desc_parts = []
            ac_bullets = []
            continue

        # ── Description continuation (rare — handles soft-wrapped lines) ─────
        if in_description and line.strip() and not line.startswith("Parent:") \
                and not line.startswith("Tags:") and not line.startswith("**"):
            desc_parts.append(line.strip())

    # Final story (file may not end with ---)
    _flush()
    return stories


def main(out_path: str) -> None:
    script_dir = Path(__file__).parent
    stories_dir = script_dir.parent / "ado" / "user_stories"

    if not stories_dir.exists():
        raise FileNotFoundError(f"User stories directory not found: {stories_dir}")

    all_stories: list[dict] = []

    for stem, (feature_name, domain_code) in DOMAIN_META.items():
        md_file = stories_dir / f"{stem}.md"
        if not md_file.exists():
            print(f"  [WARN] Missing file: {md_file}")
            continue
        parsed = parse_file(md_file, feature_name, domain_code)
        print(f"  {stem.upper()}: {len(parsed)} stories parsed from {md_file.name}")
        all_stories.extend(parsed)

    out_file = Path(out_path)
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(all_stories)

    print(f"\nTotal: {len(all_stories)} stories → {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse MCSB v2 user story .md files to CSV")
    parser.add_argument("--out", default="ado_stories.csv", help="Output CSV path")
    args = parser.parse_args()
    main(args.out)

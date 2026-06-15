# Code Review — ADO Import Scripts

**Reviewed by**: Qwen3:30b-a3b (local) + Claude Sonnet 4.6 (validation)
**Date**: 2026-06-15
**Phase**: 28
**Files reviewed**: `ado_config.py`, `parse_stories.py`, `import_to_ado.py`

---

## Qwen3 Findings

```
[CRITICAL] parse_stories.py:38 — Regex for story title breaks if title contains double
           asterisks, causing incomplete parsing and data loss.
           Fix: add defensive strip of surrounding ** before regex match.

[HIGH]     import_to_ado.py:104 — ADO_PROJECT not escaped in WIQL query string — single
           quote injection possible if project name contains apostrophe.
           Fix: escape ADO_PROJECT same as title: .replace("'", "''")

[HIGH]     import_to_ado.py:load_csv — Missing CSV file raises bare FileNotFoundError
           with no user guidance.
           Fix: explicit existence check with actionable message.

[HIGH]     import_to_ado.py:create_user_story — HTTP 429 (rate limit) not retried,
           causes partial failures on large imports.
           Fix: check Retry-After header and sleep+retry once.

[MEDIUM]   parse_stories.py — AC bullet containing literal '---' could cause early flush.
           (False positive — '---' only triggers flush when line.strip() == '---',
            AC bullets start with '- ' not '---'. No fix needed.)

[MEDIUM]   import_to_ado.py — AREA_PATH/ITERATION_PATH flagged as unused.
           (False positive — both ARE used in create_feature and create_user_story.)

[LOW]      import_to_ado.py:find_feature_by_title — No feedback when WIQL search runs.
           Fix: add debug print (optional).
```

---

## Claude Validation

| Finding | Valid? | Action |
|---|---|---|
| CRITICAL regex | Partial — parser tested (160/160 pass). No `**` in titles. | Add defensive assertion |
| HIGH WIQL injection | Valid — ADO_PROJECT unescaped | Fix applied |
| HIGH CSV missing | Valid | Fix applied |
| HIGH 429 retry | Valid | Fix applied (single retry) |
| MEDIUM AC `---` | False positive | No change |
| MEDIUM unused vars | False positive | No change |
| LOW debug print | Optional | Not applied (noise) |

---

## Verdict: **Needs minor fixes** (3 applied — see below)

Parser is functionally correct (validated against all 160 stories). Three real issues fixed before first live run.

---

## Fixes Applied

### 1. WIQL injection — `import_to_ado.py:find_feature_by_title`
Escape `ADO_PROJECT` in WIQL query string (was only escaping title).

### 2. CSV existence check — `import_to_ado.py:run_import`
Explicit `Path.exists()` check with actionable error message before `load_csv`.

### 3. HTTP 429 retry — `import_to_ado.py:create_user_story`
On 429, read `Retry-After` header, sleep, retry once. Avoids partial failures on large imports.

---

## Copilot Handover Notes

- Run order: `parse_stories.py` → `import_to_ado.py --dry-run` → `import_to_ado.py`
- Config lives entirely in `ado_config.py` — no other file needs editing
- PAT via `export ADO_PAT=<token>` only — never in code
- Features are idempotent (title search before create). User Stories are NOT — delete before re-run on failure
- All 160 stories validated: 12 domains, correct counts, no empty description/AC fields

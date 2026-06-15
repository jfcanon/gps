# MCSB v2+v3 Gap Assessment — Industry Benchmark

**Research by**: Qwen3:30b-a3b (local) + Claude Sonnet 4.6 (analysis)
**Date**: 2026-06-15
**Phase**: 33

---

## Industry Benchmark (Qwen3 findings)

### Duration
- **6–10 weeks** wall-clock for medium-large Azure enterprise (100–500 subscriptions, 5–10 landing zones)
- **3–5 person team** (security architects + engineers)
- **4–6 hours per control** average (manual + documentation)

### Effort by Phase
| Phase | % of Total | Hours (at 760h mid-range) |
|---|---|---|
| Discovery | 30% | ~228h |
| Analysis | 50% | ~380h |
| Reporting | 20% | ~152h |

### Automation Impact
- **45 script_simple controls** (Azure Policy GUIDs) → 70–85% effort reduction per control
- **40 script_complex controls** (policy name mapping only) → 40–50% reduction
- Automating the 45 built-in controls first saves **300+ hours**

### MCSB vs Other Frameworks
- MCSB v2+v3 covers 12 domains vs CIS Benchmark's 8 → **30–50% longer** than CIS/STAR
- MCSB includes operational/organisational controls (IR, BR, DS, GS) that CIS omits

---

## Our Estimate vs Industry

| Metric | Our Script (v1) | Industry Norm |
|---|---|---|
| Hours/control | 0.95h | 4–6h |
| Total hours | 152h | 600–1,000h |
| Working days | 19 days | 75–125 days |
| Gap | — | **4–6× underestimated** |

**Root cause**: Initial formula used 1.0h base — industry baseline should be 3.0–4.0h per story, reflecting documentation overhead, stakeholder interviews, evidence collection, and exception tracking that any real assessment requires.

---

## Revised Effort Formula

```
base_hours = 3.0  (industry-calibrated)

+ 2.0  if policy_status == "none"          (manual audit: no automation support)
+ 2.0  if automation_class == "manual_only" (process/doc control: no tooling)
+ 1.0  if automation_class == "script_complex" (partial automation, custom query needed)
- 1.0  if policy_status == "confirmed"     (automated check covers most effort)

min = 2.0  (floor: even confirmed+simple needs review + docs)
```

Expected output: ~640h total (4.0h avg/story) — within industry 600–1,000h range.

---

## Top 3 Effort Reduction Strategies (Qwen3)

1. **Automate the 45 built-in Policy controls first** — saves 300+ hours; these are script_simple and can be scripted as Azure CLI / REST compliance checks
2. **Pre-define subscription groupings for parallel analysis** — run domain teams in parallel (e.g., NS + DP team, IM + PA team) reducing wall-clock to 4–6 weeks
3. **Use Microsoft MCSB Azure Policy initiative templates** — standardised scanning vs manual checks; reduces Analysis phase by 40%

---

## Implications for This Project

| Item | Value |
|---|---|
| Revised total estimate | ~640h |
| Working days (1 person) | ~80 days (4 months) |
| Working days (3-person team) | ~27 days (5.5 weeks) |
| Minimum viable scope (automated only) | ~45 controls × 2h = 90h (~11 days) |
| Manual-only controls | 90 stories (policy_status=none) — highest effort |

**Priority recommendation**: Implement the 45 script_simple controls (Azure Policy compliance checks) first for quick wins, then tackle the 90 manual-only stories using the user story structure already built.

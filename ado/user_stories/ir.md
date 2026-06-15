# Incident Response (IR) — User Stories

4 user stories: 4 pure v2.
Phase 21 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-IR] Incident Response — MCSB v2

---

## [SEC-IR] Incident Response — 4 Controls, 4 Stories

### 1 Establish an Incident Response Plan and Handling [pure v2]

**[SEC-1] Establish an Incident Response Plan and Handling**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess incident response documentation completeness — PICERL phase coverage (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), top threat scenario runbook availability (ransomware, account compromise, data exfiltration), Sentinel Logic Apps playbooks for automated containment, IR team contact and escalation path documentation, and annual IR plan review scheduling — so that IR-1 gaps in incident response planning and process readiness are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for incident response plan documentation in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on IR plan documentation and Sentinel playbook coverage manual audit.

**Acceptance Criteria:**
- Incident response plan IR-1 configuration assessed against MCSB baseline and tenants with missing PICERL phase documentation, incomplete threat scenario runbooks, absent Sentinel Logic Apps playbooks, unverified escalation paths, or overdue annual review schedules identified.
- Azure Policy coverage for incident response plan controls evaluated; built-ins absent for this control — assessment relies on IR plan documentation completeness and Sentinel playbook coverage manual audit.
- Gap findings documented with remediation scope and affected PICERL phase coverage, threat runbook availability, and Sentinel playbook automation configurations noted.

---

### 2 Preparation: Setup Incident Notification [pure v2]

**[SEC-2] Preparation: Setup Incident Notification**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess incident notification infrastructure — Defender for Cloud security contact configuration (email and phone), alert notification enablement for all severity levels, Action Group deployment for High severity alerts (email, SMS, and Teams webhook), Sentinel incident notification Action Group configuration, and escalation matrix documentation and testing evidence — so that IR-2 gaps in notification coverage and team responsiveness are identified. Key Azure Policy built-ins applicable: ["Email notification for high severity alerts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Email notification to subscription owner for high severity alerts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- Incident notification IR-2 configuration assessed against MCSB baseline and subscriptions with missing security contact configuration, disabled alert notifications for any severity level, absent High severity Action Groups, or undocumented and untested escalation matrices identified.
- Azure Policy compliance evaluated for: ["Email notification for high severity alerts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ["Email notification to subscription owner for high severity alerts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected security contact settings, Action Group configurations, and escalation matrix test records noted.

---

### 3 Detection and Analysis: Create Incidents Based on High Quality Alerts [pure v2]

**[SEC-3] Detection and Analysis: Create Incidents Based on High Quality Alerts**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess alert quality and incident creation workflow — Sentinel analytics rule tuning and review cadence for all MCSB v2 domains, documented false positive suppression approvals, false positive rate tracking methodology, incident correlation rule configuration (multiple alerts to single incident), UEBA entity insights enablement and usage in triage, and Microsoft Defender Threat Intelligence (MDTI) integration status — so that IR-3 gaps in alert accuracy and incident correlation effectiveness are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Sentinel alert quality controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Sentinel analytics rule coverage and UEBA configuration manual audit.

**Acceptance Criteria:**
- Alert quality IR-3 configuration assessed against MCSB baseline and environments with un-tuned analytics rules, undocumented or unapproved false positive suppression, absent false positive rate tracking, missing incident correlation rules, or unutilized UEBA entity insights and MDTI integration identified.
- Azure Policy coverage for alert quality controls evaluated; built-ins absent for this control — assessment relies on Sentinel analytics rule tuning records, suppression approval documentation, and MDTI integration configuration manual audit.
- Gap findings documented with remediation scope and affected analytics rule domains, suppression approval records, incident correlation configurations, and UEBA and MDTI integration status noted.

---

### 4 Detection and Analysis: Investigate an Incident [pure v2]

**[SEC-4] Detection and Analysis: Investigate an Incident**
Parent: [SEC-IR] Incident Response — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess incident investigation readiness — Sentinel investigation graph availability and SOC team training evidence, documented KQL log queries for common threat scenarios (lateral movement, data exfiltration, privilege escalation), Defender for Endpoint timeline and live response capability testing records, evidence collection SOP documentation, and chain of custody procedures for forensic artifacts — so that IR-4 gaps in investigation effectiveness and forensic evidence integrity are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for incident investigation procedures in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Sentinel investigation capability and SOC procedure documentation manual audit.

**Acceptance Criteria:**
- Investigation readiness IR-4 configuration assessed against MCSB baseline and environments with unavailable Sentinel investigation graphs, untrained SOC teams, missing KQL query libraries for key threat scenarios, untested Defender for Endpoint live response, or incomplete evidence collection and chain of custody SOPs identified.
- Azure Policy coverage for incident investigation controls evaluated; built-ins absent for this control — assessment relies on Sentinel investigation graph configuration, Defender for Endpoint live response testing records, and forensic SOP documentation manual audit.
- Gap findings documented with remediation scope and affected Sentinel investigation tooling, KQL query coverage, Defender for Endpoint capabilities, and forensic artifact chain of custody procedures noted.

# ADO Features — MCSB v2 Security Domains

12 Features, one per MCSB v2 (preview) security domain.
Parent Feature: "Security Gap Assessment" (existing — do NOT recreate)
Import as **Feature** work items in Azure DevOps.

---

## Feature 1 — Network Security

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-NS] Network Security — MCSB v2 |
| **Tags** | MCSB-v2; NS; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #1: Network Security (NS) Baseline Enforcement

**Description**:
Azure network perimeter controls are inconsistently applied across the estate. PaaS services remain publicly accessible without private endpoints, firewall rules are fragmented across subscriptions, and no centralized traffic inspection exists for east-west traffic. This domain enforces zero-trust network principles: private-by-default for all PaaS, centralized egress via Azure Firewall Premium, DDoS protection on all internet-facing VNets, and WAF in Prevention mode for all public web entry points.

**Controls List** (10 v2 controls, 50 v3 resource stories):
- NS-1 Establish Network Segmentation Boundaries [7 v3 resources]
- NS-2 Secure Cloud Native Services with Network Controls [27 v3 resources]
- NS-3 Deploy Firewall at Edge of Enterprise Network [3 v3 resources]
- NS-4 Deploy Intrusion Detection/Prevention Systems [pure v2]
- NS-5 Deploy DDoS Protection [2 v3 resources]
- NS-6 Deploy Web Application Firewall [3 v3 resources]
- NS-7 Simplify Network Security Configuration [1 v3 resource]
- NS-8 Detect and Disable Insecure Services and Protocols [pure v2]
- NS-9 Connect On-Premises or Cloud Network Privately [6 v3 resources]
- NS-10 Ensure Domain Name System (DNS) Security [1 v3 resource]

**Acceptance Criteria (BDD)**:
- Given: Azure PaaS services expose public endpoints and NSG rules allow broad inbound access
- When: NS baseline enforcement is applied across all subscriptions in scope
- Then: All PaaS services accessible only via private endpoint; Firewall Premium routes all egress; IDPS in Alert+Deny; WAF in Prevention mode; no TLS below 1.2
- And then: Defender for Cloud NS recommendations at zero critical; Azure Policy compliance ≥95% for NS initiative

**Success Measures**:
- AC-1: 100% of in-scope PaaS resources have public network access disabled and private endpoint deployed
- AC-2: Azure Firewall Premium deployed in hub; Threat Intelligence Alert+Deny; IDPS enabled
- AC-3: DDoS Network Protection Standard on all VNets with public IPs; WAF Prevention mode on all public entry points

**Azure Policies Assessment**:
- "Deny public network access" — apply to: Storage, SQL, Cosmos DB, Key Vault, Service Bus, Event Hubs, AKS
- "App Service should use private link" — audit and enforce
- "TLS minimum version 1.2" — audit across App Service, Storage, SQL, API Management
- "Azure Firewall should be enabled" — audit hub VNets
- "DDoS protection standard should be enabled" — audit all VNets
- "Web Application Firewall should be enabled for Application Gateway" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for DNS: covers NS-10 threat detection gap (DNS tunneling, malicious domains)
- Defender for Networks (Network Traffic Analytics): covers NS-7 gap (traffic pattern anomalies)
- Defender for Cloud NS recommendations: "Adaptive network hardening recommendations" — covers NS-1 gaps in NSG rules
- Manual gap: NS-4 IDPS requires Azure Firewall Premium (Defender does not replace IDPS)

**Release Notes**: NA

---

## Feature 2 — Identity Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-IM] Identity Management — MCSB v2 |
| **Tags** | MCSB-v2; IM; azure-infra-sec; security-gap |
| **Priority** | 1 |

**Title**: Security Domain #2: Identity Management (IM) Baseline Enforcement

**Description**:
Identity attack surface is poorly bounded: legacy authentication protocols are not blocked, service principals accumulate without lifecycle governance, and Conditional Access policies do not enforce compliant device or risk-based controls consistently. This domain enforces Entra ID as sole identity provider, eliminates all legacy auth paths, mandates MFA via Conditional Access for all users, and replaces all service principal secrets with Managed Identity across Azure workloads.

**Controls List** (8 v2 controls, 7 v3 resource stories):
- IM-1 Use Centralized Identity and Authentication System [1 v3 resource]
- IM-2 Protect Identity and Authentication Systems [pure v2]
- IM-3 Manage Application Identities Securely and Automatically [2 v3 resources]
- IM-4 Authenticate Server and Services [2 v3 resources]
- IM-5 Use Single Sign-On (SSO) for Application Access [1 v3 resource]
- IM-6 Use Strong Authentication Controls [pure v2]
- IM-7 Restrict Resource Access Based on Conditions [1 v3 resource]
- IM-8 Restrict the Exposure of Credential and Secrets [pure v2]

**Acceptance Criteria (BDD)**:
- Given: Legacy auth not fully blocked, service principals hold long-lived secrets, MFA coverage incomplete
- When: IM baseline enforcement applied via Conditional Access and Managed Identity migration
- Then: All legacy auth blocked by CA policy; 100% workloads using Managed Identity (no client secrets in deployments); MFA enforced for all users via CA
- And then: Identity Protection risk policies active; Azure AD Connect Health green; secret scanning shows zero new violations in repos

**Success Measures**:
- AC-1: Zero service principals with secrets >90 days; 100% Azure workloads using Managed Identity
- AC-2: Conditional Access blocks legacy auth for 100% of users; MFA required for all sign-ins
- AC-3: Identity Protection user/sign-in risk policies: High → block; risky sign-in alerts piped to Sentinel

**Azure Policies Assessment**:
- "MFA should be enabled on accounts with owner permissions" — enforce
- "Service fabric clusters should only use Azure Active Directory for client authentication" — audit
- "Managed identity should be used in function apps / app service" — enforce
- "Guest accounts with owner/contributor/reader permissions should be removed" — audit

**Microsoft Defender Variance Mapping**:
- Microsoft Defender for Identity (MDI): covers IM-2 gap (on-premises AD attack detection, pass-the-hash, DCSync)
- Entra ID Identity Protection: covers IM-2 and IM-6 risk-based sign-in detection
- Defender for Cloud Apps (MCAS): covers IM-7 conditional access session controls
- Manual gap: IM-3 Managed Identity migration requires application code changes — Defender cannot auto-remediate

**Release Notes**: NA

---

## Feature 3 — Privileged Access

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-PA] Privileged Access — MCSB v2 |
| **Tags** | MCSB-v2; PA; azure-infra-sec; security-gap |
| **Priority** | 1 |

**Title**: Security Domain #3: Privileged Access (PA) Baseline Enforcement

**Description**:
Standing privileged access is the primary lateral movement amplifier in Azure environments. Owner and Contributor roles are assigned permanently at subscription scope, PIM is not enforced for any privileged roles, and privileged actions are performed from shared, non-hardened workstations. This domain eliminates all standing privileged access via PIM, enforces JIT activation with approval for all Owner/Contributor roles, deploys PAW controls, and implements Customer Lockbox for all Microsoft support scenarios.

**Controls List** (8 v2 controls, 4 v3 resource stories):
- PA-1 Separate and Limit Highly Privileged Users [pure v2]
- PA-2 Avoid Standing Access for User Accounts and Permissions [1 v3 resource: Automation]
- PA-3 Manage Lifecycle of Identities and Entitlements [pure v2]
- PA-4 Review and Reconcile User Access Regularly [pure v2]
- PA-5 Set Up Emergency Access [pure v2]
- PA-6 Use Privileged Access Workstations [1 v3 resource: Cloud Shell]
- PA-7 Follow Just Enough Administration (Least Privilege) Principle [1 v3 resource: Lighthouse]
- PA-8 Choose Approval Process for Microsoft Support Access [1 v3 resource: Customer Lockbox]

**Acceptance Criteria (BDD)**:
- Given: Permanent Owner/Contributor assignments at subscription scope exist; no PAW enforced; Customer Lockbox not enabled
- When: PIM activation required for all privileged roles; PAW Conditional Access policy enforced; Customer Lockbox enabled
- Then: Zero permanent Owner/Contributor assignments; all privileged role activations require justification + approval; Lockbox approver assigned
- And then: PIM access review shows no permanent roles; PAW CA policy blocks activation from non-compliant devices; Lockbox requests logged to Sentinel

**Success Measures**:
- AC-1: Zero permanent Owner/Contributor assignments at subscription scope; all roles eligible via PIM
- AC-2: PIM activation: ≤8h time-bound; approval required for Owner; MFA on activation
- AC-3: Customer Lockbox enabled; approver role assigned; auto-deny after 12h; audit log → Sentinel

**Azure Policies Assessment**:
- "Audit usage of custom RBAC roles" — audit (prefer built-in roles)
- "Deprecated accounts with owner permissions should be removed" — enforce
- "There should be more than one owner assigned to your subscription" — audit (min 2)
- "Subscriptions should have a contact email address for security issues" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: "Privileged identity management should be used to protect subscriptions" recommendation — covers PA-1 gap
- Defender for Cloud: "Enable MFA for accounts with owner permissions" — covers PA activation gap
- Manual gap: PA-6 PAW enforcement requires Conditional Access + Intune compliance policy — no Defender auto-remediation
- Manual gap: PA-5 break-glass account configuration requires manual process and testing

**Release Notes**: NA

---

## Feature 4 — Data Protection

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-DP] Data Protection — MCSB v2 |
| **Tags** | MCSB-v2; DP; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #4: Data Protection (DP) Baseline Enforcement

**Description**:
Sensitive data is not classified, encryption key ownership is undefined, and TLS enforcement is inconsistent across database and storage services. Multiple storage accounts allow public blob access, Key Vault access uses legacy access policies instead of RBAC, and no certificate lifecycle management exists for TLS certs expiring in production. This domain enforces AES-256 encryption at rest across all data stores, CMK for Confidential/Restricted data, TLS 1.2 minimum, and Purview-based data classification with DLP policy coverage.

**Controls List** (8 v2 controls, 28 v3 resource stories):
- DP-1 Discover, Classify, and Label Sensitive Data [3 v3 resources]
- DP-2 Monitor Anomalies and Threats Targeting Sensitive Data [3 v3 resources]
- DP-3 Encrypt Sensitive Data in Transit [6 v3 resources]
- DP-4 Enable Data at Rest Encryption by Default [7 v3 resources]
- DP-5 Use Customer-Managed Key When Required [5 v3 resources]
- DP-6 Use a Secure Key Management Process [3 v3 resources]
- DP-7 Use a Secure Certificate Management Process [pure v2]
- DP-8 Ensure Security of Key and Certificate Repository [1 v3 resource: Data Box]

**Acceptance Criteria (BDD)**:
- Given: Sensitive data location unknown, public blob access enabled on storage, TLS not enforced on all database services, Key Vault uses access policies
- When: DP baseline enforcement applied via Purview scan, Policy assignments, and Key Vault RBAC migration
- Then: All data classified; public blob access disabled on all storage accounts; TLS 1.2 enforced on all database connections; Key Vault RBAC model active
- And then: Purview scan coverage ≥90% of data stores; Defender for Storage/SQL anomaly alerts routing to Sentinel; CMK deployed for Confidential data stores

**Success Measures**:
- AC-1: Purview scan covers 100% of storage accounts and SQL databases; sensitivity labels applied
- AC-2: Zero storage accounts with allow-blob-public-access enabled; TLS 1.2 minimum on all database services
- AC-3: CMK deployed for all Confidential/Restricted data stores; Key Vault RBAC model; soft delete + purge protection on all vaults

**Azure Policies Assessment**:
- "Storage accounts should prevent shared key access" — enforce
- "Storage account should use a private link connection" — audit
- "SQL databases should have vulnerability findings resolved" — enforce
- "TLS version should be the latest for API App / Function App / Web App" — enforce
- "Azure Cosmos DB accounts should have firewall rules" — enforce
- "Key vaults should have soft delete enabled / purge protection enabled" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Storage: covers DP-2 gap (anomalous blob access, malware upload, suspicious IP access)
- Defender for SQL: covers DP-2 gap (SQL injection, unusual query patterns, data exfiltration)
- Defender for Key Vault: covers DP-6 gap (unusual access patterns, compromised credentials)
- Manual gap: DP-5 CMK implementation requires Key Vault provisioning and key assignment per service — cannot be automated by Defender

**Release Notes**: NA

---

## Feature 5 — Asset Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-AM] Asset Management — MCSB v2 |
| **Tags** | MCSB-v2; AM; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #5: Asset Management (AM) Baseline Enforcement

**Description**:
Azure resource inventory is fragmented: no consistent tagging policy, unauthorized resource types deployed in production subscriptions, and stale resources (orphaned disks, unused NICs, abandoned PIPs) accumulate without lifecycle governance. This domain establishes Azure Policy-driven resource governance: mandatory tagging, allowed resource types, approved regions enforcement, and Resource Graph-based inventory reporting with automated stale resource detection.

**Controls List** (5 v2 controls, 6 v3 resource stories):
- AM-1 Track Asset Inventory and Their Risks [2 v3 resources: Resource Graph, Migrate]
- AM-2 Use Only Approved Services [1 v3 resource: Policy]
- AM-3 Ensure Security of Asset Lifecycle Management [2 v3 resources: Resource Mover, DevTest Labs]
- AM-4 Limit Access to Asset Management [1 v3 resource: Resource Manager]
- AM-5 Use Only Approved Applications in Virtual Machine [pure v2]

**Acceptance Criteria (BDD)**:
- Given: No tagging policy enforced, unauthorized resource types exist, no stale resource detection process
- When: Azure Policy initiatives applied at management group and Resource Graph queries operationalized
- Then: All resources tagged (Environment, Owner, CostCenter, DataClassification); unauthorized resource types denied; stale resources reported weekly
- And then: AM Policy compliance ≥95%; Defender for Cloud asset inventory showing complete coverage; orphaned resource count trending to zero

**Success Measures**:
- AC-1: 100% of resources tagged with mandatory tags; deny policy blocks non-tagged deployments
- AC-2: Allowed resource types policy active at management group; no unauthorized deployments in 30 days
- AC-3: Stale resource detection query runs weekly via Automation; orphaned disk/NIC/PIP count reported

**Azure Policies Assessment**:
- "Require a tag and its value on resources" — enforce (Environment, Owner, CostCenter, DataClassification)
- "Allowed locations" — enforce (deny unapproved regions)
- "Not allowed resource types" — enforce at management group
- "Virtual machines should be connected to a specified workspace" — enforce (inventory via AMA)

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: asset inventory and Secure Score cover AM-1 risk view
- Defender for Cloud: "Adaptive application controls should be enabled on virtual machines" — covers AM-5 gap
- Manual gap: AM-3 decommission procedure (data wipe, disk secure erase) requires runbook — Defender cannot enforce physical disposal

**Release Notes**: NA

---

## Feature 6 — Logging and Threat Detection

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-LT] Logging and Threat Detection — MCSB v2 |
| **Tags** | MCSB-v2; LT; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #6: Logging and Threat Detection (LT) Baseline Enforcement

**Description**:
Diagnostic settings are not deployed consistently: only ~40% of resources forward logs to Log Analytics. NSG flow logs are absent on most subnets. No centralized Sentinel workspace exists — alerts scatter across multiple workspaces with no cross-correlation. Time synchronization is unvalidated, creating timestamp skew that breaks Sentinel correlation rules. This domain mandates diagnostic settings on all resources via Azure Policy (DeployIfNotExists), centralizes all log sources into a single Sentinel workspace, and enforces log retention compliance.

**Controls List** (7 v2 controls, 2 v3 resource stories):
- LT-1 Enable Threat Detection Capabilities [1 v3 resource: Defender for Cloud]
- LT-2 Enable Threat Detection for Identity and Access Management [pure v2]
- LT-3 Enable Logging for Security Investigation [pure v2]
- LT-4 Enable Network Logging for Security Investigation [pure v2]
- LT-5 Centralize Security Log Management and Analysis [2 v3 resources: Sentinel, Monitor]
- LT-6 Configure Log Storage Retention [pure v2]
- LT-7 Use Approved Time Synchronization Sources [pure v2]

**Acceptance Criteria (BDD)**:
- Given: Diagnostic settings missing on most resources; no Sentinel workspace; NSG flow logs absent; log retention undefined
- When: LT Policy initiative (diagnostic settings DeployIfNotExists) applied and Sentinel workspace operational
- Then: 100% of in-scope resources forwarding logs to Log Analytics; NSG flow logs enabled on all NSGs; Sentinel analytics rules active for all MCSB v2 domains
- And then: Log Analytics workspace data connector coverage ≥95%; retention: 90d interactive + 1yr archive configured; Sentinel alert → incident pipeline validated

**Success Measures**:
- AC-1: 100% of resource types have diagnostic settings deployed (Policy DeployIfNotExists remediation complete)
- AC-2: NSG flow logs v2 on all NSGs; Traffic Analytics enabled; Azure Firewall diagnostic logs forwarded
- AC-3: Sentinel workspace: all Azure log sources connected; MCSB v2 analytics rule coverage per domain

**Azure Policies Assessment**:
- "Diagnostic settings should be enabled for all resource types" (DeployIfNotExists) — enforce
- "Azure Defender for [SQL/Storage/Servers/Containers/KeyVault] should be enabled" — enforce
- "Log Analytics agent should be installed on VMs / VMSS" — enforce (or AMA equivalent)
- "Flow log should be configured for every network security group" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: covers LT-1 across all plans (Servers, Storage, SQL, Containers, AppService, KeyVault, DNS, ARM)
- Microsoft Sentinel: covers LT-5 centralization gap; Sentinel UEBA covers LT-2 identity threat detection
- Defender for DNS: covers LT-4 DNS query logging gap
- Manual gap: LT-7 time sync validation requires custom policy or Azure Monitor query — no native Defender check

**Release Notes**: NA

---

## Feature 7 — Incident Response

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-IR] Incident Response — MCSB v2 |
| **Tags** | MCSB-v2; IR; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #7: Incident Response (IR) Baseline Enforcement

**Description**:
No documented IR plan exists for Azure-specific threat scenarios. Security contact is not configured in Defender for Cloud, so critical alerts are not routed to the right team. Sentinel playbooks for automated containment are absent, and post-incident review is ad hoc with no structured lessons-learned process. This domain formalizes the IR lifecycle: documented plan with runbooks for ransomware/account compromise/exfiltration, Sentinel playbooks for automated containment, alert routing to a defined security contact, and a structured post-incident review cadence.

**Controls List** (4 v2 controls, 0 v3 resource stories — all pure v2):
- IR-1 Establish an Incident Response Plan and Handling [pure v2]
- IR-2 Preparation — Setup Incident Notification [pure v2]
- IR-3 Detection and Analysis — Create Incidents Based on High Quality Alerts [pure v2]
- IR-4 Detection and Analysis — Investigate an Incident [pure v2]

**Acceptance Criteria (BDD)**:
- Given: No IR plan documented, no security contact in Defender for Cloud, no Sentinel playbooks for containment
- When: IR plan authored, security contact configured, playbooks deployed and tested
- Then: IR plan covers all PICERL phases; security contact receives High+ alerts; 3 containment playbooks operational (account disable, isolate VM, block IP)
- And then: Security contact acknowledged alerts in <15 min test; playbooks tested via Sentinel incident simulation; IR plan reviewed annually

**Success Measures**:
- AC-1: IR plan documented and approved; runbooks for: ransomware, account compromise, data exfiltration
- AC-2: Security contact (email + phone) in Defender for Cloud; Action Group notifies SOC for High+ severity
- AC-3: Sentinel analytics: false positive rate <20%; UEBA active; Sentinel investigation graph validated in tabletop exercise

**Azure Policies Assessment**:
- "Subscriptions should have a contact email address for security issues" — enforce
- "Email notification for high severity alerts should be enabled" — enforce
- "Email notification to subscription owners for high severity alerts should be enabled" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: covers IR-2 gap (security contact, alert notification)
- Microsoft Sentinel: covers IR-3 gap (analytics rules, alert → incident correlation) and IR-4 gap (investigation graph, UEBA)
- Manual gap: IR-1 IR plan documentation requires human authoring — no tool automates IR plan content
- Manual gap: IR-4 live response and forensics training requires scheduled exercises

**Release Notes**: NA

---

## Feature 8 — Posture and Vulnerability Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-PV] Posture and Vulnerability Management — MCSB v2 |
| **Tags** | MCSB-v2; PV; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #8: Posture and Vulnerability Management (PV) Baseline Enforcement

**Description**:
Defender for Cloud Secure Score is below 50%, critical CVEs remain unpatched beyond 30 days on production VMs, and no automated vulnerability scanning exists for container images. OS patch management is manual and reactive. No formal penetration testing or red team cadence exists to validate control effectiveness. This domain activates Defender for Servers P2 (Qualys/MDE vulnerability assessment), deploys Azure Update Manager for automated patching, sets CVE SLAs (Critical: 48h, High: 7d), and establishes annual red team operations.

**Controls List** (7 v2 controls, 2 v3 resource stories):
- PV-1 Run Automated Vulnerability Scans [1 v3 resource: Defender for Cloud]
- PV-2 Run Automated OS Patch Management [pure v2]
- PV-3 Establish Secure Configurations for Compute Resources [pure v2]
- PV-4 Audit and Enforce Secure Configurations [pure v2]
- PV-5 Perform Vulnerability Assessments [1 v3 resource: Advisor]
- PV-6 Rapidly and Automatically Remediate Vulnerabilities [pure v2]
- PV-7 Conduct Regular Red Team Operations [pure v2]

**Acceptance Criteria (BDD)**:
- Given: Secure Score <50%; no patch management automation; critical CVEs unpatched >30 days; no container image scanning
- When: Defender for Servers P2 activated; Azure Update Manager schedules deployed; container scanning enabled
- Then: All VM CVEs assessed; critical CVE patch SLA enforced (48h); Secure Score ≥70%; container image scanning in CI pipeline
- And then: Patch compliance report monthly; no critical CVEs open >48h in production; Defender for Cloud recommendations at zero critical

**Success Measures**:
- AC-1: Defender for Cloud Secure Score ≥70%; zero critical recommendations in production subscriptions
- AC-2: Azure Update Manager: patch compliance ≥98% for critical patches within 48h SLA
- AC-3: Container image scanning (Defender for Containers): no Critical CVEs in production images

**Azure Policies Assessment**:
- "A vulnerability assessment solution should be enabled on virtual machines" — enforce
- "Vulnerabilities in container images running in Azure Kubernetes Service should be remediated" — enforce
- "System updates should be installed on your machines" — enforce
- "Vulnerabilities in your virtual machines should be remediated" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Servers P2: covers PV-1 gap (Qualys integrated VA, MDE-based VA)
- Defender for Containers: covers PV-1 gap for container images (registry scan + runtime)
- Azure Advisor: covers PV-5 gap (security recommendations aggregation)
- Manual gap: PV-7 red team operations require external engagement — Defender attack path analysis supplements but does not replace

**Release Notes**: NA

---

## Feature 9 — Endpoint Security

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-ES] Endpoint Security — MCSB v2 |
| **Tags** | MCSB-v2; ES; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #9: Endpoint Security (ES) Baseline Enforcement

**Description**:
MDE coverage is incomplete: Linux VMs and container workloads lack EDR sensor deployment. Antimalware exclusions have sprawled with no governance, undermining detection fidelity. Container registries push images with known CVEs into production with no pre-deploy scan gate. IoT devices lack any endpoint monitoring. This domain enforces 100% MDE deployment via Defender for Cloud auto-provisioning, locks down antimalware exclusions, establishes container image scan gates in CI/CD, and deploys Defender for IoT on OT/ICS networks.

**Controls List** (3 v2 controls, 14 v3 resource stories):
- ES-1 Use Endpoint Detection and Response (EDR) [5 v3 resources: VMs Linux/Windows, VMSS, Arc Servers, Arc K8s]
- ES-2 Use Modern Anti-Malware Software [pure v2]
- ES-3 Ensure Anti-Malware Software and Signatures Updated [9 v3 resources: Container Registry, Instances, AKS, HCI K8s, ARO, Defender for IoT, IoT Hub, IoT Central, Sphere]

**Acceptance Criteria (BDD)**:
- Given: MDE missing on Linux VMs; container images deployed with CVEs; IoT devices unmonitored; antimalware exclusion list undocumented
- When: MDE auto-provisioning enabled for all VM types; container scan gate in CI; Defender for IoT deployed
- Then: 100% VM coverage (Windows + Linux); all container images scanned pre-deploy; IoT device inventory in Defender for IoT; exclusion list documented and reviewed
- And then: MDE telemetry flowing to Sentinel; no Critical CVE images in production; Defender for IoT alerts routing to Sentinel; antimalware health report weekly

**Success Measures**:
- AC-1: MDE deployed on 100% of VMs (Windows + Linux) and Arc-enabled servers; EDR in Block mode
- AC-2: Container image scan gate: CI pipeline blocks on Critical CVE; no exceptions in production
- AC-3: Defender for IoT: OT sensor deployed; device inventory complete; alerts → Sentinel

**Azure Policies Assessment**:
- "Microsoft Defender for Endpoint agent should be installed" — enforce (VMs, VMSS)
- "Azure Defender for container registries should be enabled" — enforce
- "Endpoint protection should be installed on your machines" — enforce
- "Ensure that 'Endpoint Protection' is installed on VMs" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Servers P2: covers ES-1 gap (MDE deployment, EDR, antimalware)
- Defender for Containers: covers ES-3 gap (registry scanning, runtime threat detection for AKS/ARO)
- Defender for IoT: covers ES-3 gap for OT/IoT devices (agentless OT monitoring)
- Manual gap: ES-2 antimalware exclusion governance requires policy review process — Defender reports but does not enforce exclusion limits

**Release Notes**: NA

---

## Feature 10 — Backup and Recovery

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-BR] Backup and Recovery — MCSB v2 |
| **Tags** | MCSB-v2; BR; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #10: Backup and Recovery (BR) Baseline Enforcement

**Description**:
Backup coverage is incomplete: 30% of production VMs have no backup policy, SQL databases are backed up locally without geo-redundancy, and immutable vault protection is not enabled. No backup restore test has been performed in the last 12 months. DR failover via Azure Site Recovery is configured for only 2 workloads. This domain enforces Azure Backup Policy coverage for all production workloads, enables immutable vault protection, and mandates quarterly restore testing with documented RTO/RPO validation.

**Controls List** (4 v2 controls, 2 v3 resource stories):
- BR-1 Ensure Regular Automated Backups [1 v3 resource: Backup]
- BR-2 Protect Backup and Recovery Data [pure v2]
- BR-3 Monitor Backups [pure v2]
- BR-4 Regularly Test Backup [1 v3 resource: Site Recovery]

**Acceptance Criteria (BDD)**:
- Given: 30% VMs unprotected; no immutable vault; no restore test in 12 months; SQL backups not geo-redundant
- When: Azure Backup policy deployed to all production workloads; immutable vault enabled; restore test scheduled
- Then: 100% production VMs, SQL, Blobs, and Files under backup policy; geo-redundant vault; immutable vault enabled; quarterly restore test completed
- And then: Backup compliance report shows ≥98% successful backup jobs; restore test meets RTO target; backup alert Group notifies team on failure

**Success Measures**:
- AC-1: 100% production VM/SQL/Blob/Files covered by Azure Backup policy; geo-redundant vault
- AC-2: Immutable vault enabled; soft delete (14-day); CMK for vault encryption; backup operator RBAC separated
- AC-3: Quarterly restore test executed; RTO measured and compared to target; results documented

**Azure Policies Assessment**:
- "Azure Backup should be enabled for Virtual Machines" — enforce
- "Geo-redundant backup should be enabled for Azure Database for MySQL" — enforce
- "Long-term geo-redundant backup should be enabled for Azure SQL Databases" — enforce
- "Recovery Services vaults should use private link" — audit

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: "Backup solution should be installed on virtual machines" recommendation — covers BR-1 gap
- Azure Monitor: Backup alerts via Recovery Services vault — covers BR-3 monitoring gap
- Manual gap: BR-4 restore testing requires scheduled runbook or manual execution — no Defender automation for restore validation
- Manual gap: BR-2 immutable vault configuration requires manual ARM/Portal action — policy enforces but does not auto-configure

**Release Notes**: NA

---

## Feature 11 — DevOps Security

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-DS] DevOps Security — MCSB v2 |
| **Tags** | MCSB-v2; DS; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #11: DevOps Security (DS) Baseline Enforcement

**Description**:
Security is applied post-deployment: no SAST or IaC scanning in CI/CD pipelines, threat modeling is absent from the design phase, and Azure DevOps service connections use stored secrets instead of Workload Identity Federation. Container images are deployed without supply chain verification. DAST is not integrated into release gates. This domain implements shift-left security: SAST (Checkov, CodeQL), DAST (OWASP ZAP), dependency scanning, and IaC scanning as mandatory CI/CD gates, with Workload Identity Federation for all pipeline service connections.

**Controls List** (6 v2 controls, 0 v3 resource stories — all pure v2):
- DS-1 Conduct Threat Modeling [pure v2]
- DS-2 Ensure Software Supply Chain Security [pure v2]
- DS-3 Secure DevOps Infrastructure [pure v2]
- DS-4 Integrate Static Application Security Testing [pure v2]
- DS-5 Integrate Dynamic Application Security Testing [pure v2]
- DS-6 Enforce Security of Workload Throughout DevOps Lifecycle [pure v2]

**Acceptance Criteria (BDD)**:
- Given: No SAST/DAST in pipelines; service connections use stored secrets; no threat model process; no IaC scan
- When: DS security gates enforced in all CI/CD pipelines; Workload Identity Federation on all service connections
- Then: SAST blocks Critical findings from merging; DAST blocks Critical findings from releasing; all service connections use WIF (no secrets); IaC scanned per PR
- And then: Zero stored secrets in ADO service connections; SAST coverage on all repos; DAST scan on all public web services per release; supply chain: SBOM generated per container build

**Success Measures**:
- AC-1: 100% CI pipelines with SAST (CodeQL/Checkov); zero Critical SAST findings merged in 30 days
- AC-2: 100% ADO service connections using Workload Identity Federation; no PAT in code (secret scan clean)
- AC-3: DAST in release pipeline for all internet-facing services; container SBOM generated and stored per build

**Azure Policies Assessment**:
- No native Azure Policy for DS controls (cross-cutting DevOps controls, not Azure resource controls)
- Defender for DevOps covers DS-2 (supply chain), DS-4 (SAST via CodeQL integration), DS-3 (ADO posture)
- Manual governance required for DS-1 (threat modeling) and DS-5 (DAST integration)

**Microsoft Defender Variance Mapping**:
- Defender for DevOps: covers DS-2 (dependency scan, secret scan), DS-3 (ADO security posture), DS-4 (IaC scan via Checkov integration)
- Defender for Cloud (DevOps Security): GitHub/ADO connector for code-to-cloud security posture
- Manual gap: DS-1 threat modeling has no Defender coverage — requires process and tooling (Microsoft TMT / OWASP Threat Dragon)
- Manual gap: DS-5 DAST requires pipeline integration of ZAP or equivalent — Defender does not provide DAST capability

**Release Notes**: NA

---

## Feature 12 — Governance and Strategy

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-GS] Governance and Strategy — MCSB v2 |
| **Tags** | MCSB-v2; GS; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #12: Governance and Strategy (GS) Baseline Enforcement

**Description**:
Security governance is undefined at the Azure level: no RACI for cloud security domains, no MCSB policy initiative assigned at management group, and Regulatory Compliance dashboard is not reviewed. Network, identity, and data protection strategies exist only as informal tribal knowledge with no documented policy. This domain formalizes Azure security governance: MCSB v2 policy initiative at management group, Security Benchmark compliance dashboard, documented strategy documents per domain, and defined roles/accountabilities for each security domain owner.

**Controls List** (10 v2 controls, 3 v3 resource stories):
- GS-1 Align Organization Roles, Responsibilities, and Accountabilities [1 v3 resource: Cost Management]
- GS-2 Define and Implement Enterprise Segmentation Strategy [pure v2]
- GS-3 Define and Implement Data Protection Strategy [pure v2]
- GS-4 Define and Implement Network Security Strategy [pure v2]
- GS-5 Define and Implement Security Posture Management Strategy [1 v3 resource: Policy]
- GS-6 Define and Implement Identity and Privileged Access Strategy [pure v2]
- GS-7 Define and Implement Logging, Threat Detection and IR Strategy [pure v2]
- GS-8 Define and Implement Backup and Recovery Strategy [1 v3 resource: Managed Applications]
- GS-9 Define and Implement Endpoint Security Strategy [pure v2]
- GS-10 Define and Implement DevOps Security Strategy [pure v2]

**Acceptance Criteria (BDD)**:
- Given: No RACI defined, MCSB policy initiative not assigned, no domain strategy documents, Secure Score not tracked
- When: GS governance baseline deployed: RACI approved, policy initiative assigned, Secure Score monitoring active
- Then: MCSB v2 policy initiative assigned at management group; Regulatory Compliance dashboard reviewed monthly; RACI document published; Secure Score tracked with ≥70% target
- And then: Monthly Secure Score report distributed to domain owners; all 12 security domain owners identified; strategy documents reviewed annually

**Success Measures**:
- AC-1: MCSB v2 policy initiative assigned at management group scope; Regulatory Compliance dashboard operational
- AC-2: RACI matrix approved: all 12 security domain owners identified (NS, IM, PA, DP, AM, LT, IR, PV, ES, BR, DS, GS)
- AC-3: Secure Score target ≥70%; monthly trend report; risk acceptance process documented and approved

**Azure Policies Assessment**:
- "Azure Security Benchmark / Microsoft Cloud Security Benchmark" initiative — assign at management group
- "Audit usage of custom RBAC roles" — enforce governance over role sprawl
- "Require a tag and its value on resource groups" — enforce ownership tags
- "Subscriptions should have a contact email address for security issues" — enforce

**Microsoft Defender Variance Mapping**:
- Defender for Cloud: Regulatory Compliance dashboard covers GS-5 posture management; MCSB compliance view
- Defender for Cloud: Secure Score tracks GS-5 posture management target
- Microsoft Cost Management: covers GS-1 cost governance and accountability
- Manual gap: GS-2 through GS-4, GS-6 through GS-10 strategy documents require human authoring — no Defender coverage for documentation governance

**Release Notes**: NA

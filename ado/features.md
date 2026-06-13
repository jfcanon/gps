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

**Title**: Security Domain #1: Network Security (NS) Baselines

**Description**:
This feature establishes network security baseline controls to remediate the current % of Defender Secure Score Baseline and close critical network architecture audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where network perimeter enforcement, PaaS service exposure, traffic inspection coverage, private connectivity gaps, and DNS security practices deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (10 v2 controls, 50 v3 resource stories):
- NS-1 Establish Network Segmentation Boundaries [Virtual Network, VNet NAT, Virtual WAN, Load Balancer, Traffic Manager, Peering Service, NAT Gateway]
- NS-2 Secure Cloud Native Services with Network Controls [App Service, Functions, Redis Cache, Container Apps, Databricks, Data Factory, Digital Twins, Event Grid, Event Hubs, File Sync, HPC Cache, Logic Apps, Machine Learning Service, Managed Lustre, Notification Hubs, Remote Rendering, Service Bus, SignalR Service, Spring Apps, Web PubSub, Batch, Cognitive Search, Cognitive Services, Communication Services, Communications Gateway, CDN, Database Migration Service]
- NS-3 Deploy Firewall at Edge of Enterprise Network [Firewall, Firewall Manager, Stack Edge]
- NS-4 Deploy Intrusion Detection/Prevention Systems [v2]
- NS-5 Deploy DDoS Protection [DDoS Protection, Public IP]
- NS-6 Deploy Web Application Firewall [Application Gateway, Front Door, WAF]
- NS-7 Simplify Network Security Configuration [Network Watcher]
- NS-8 Detect and Disable Insecure Services and Protocols [v2]
- NS-9 Connect On-Premises or Cloud Network Privately [VPN Gateway, Private Link, Bastion, Virtual Desktop, Nutanix on Azure, VMware Solution]
- NS-10 Ensure Domain Name System (DNS) Security [DNS]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Network Segmentation and Perimeter Coverage Assessment (NS-1, NS-3, NS-7): Assess whether VNet segmentation boundaries, NSG rules, and firewall policies are consistently defined and applied across all subscriptions and hub/spoke network topologies in scope. Identify resources deployed without defined network segment membership or missing centralized firewall coverage, including hub VNets where egress inspection is absent.
- AC-2 PaaS Service Exposure and Edge Protection Assessment (NS-2, NS-5, NS-6): Assess whether cloud-native PaaS services are accessible only via private endpoints or approved network access paths, and whether internet-facing entry points are protected by WAF policy and DDoS controls. Identify services with unrestricted public network access enabled, WAF policy gaps, or VNets without DDoS Standard protection assigned.
- AC-3 Private Connectivity, Protocol Hygiene, and DNS Security Assessment (NS-4, NS-8, NS-9, NS-10): Evaluate whether private connectivity paths (VPN Gateway, Private Link, Bastion) are in use for on-premises and cross-service access, and whether insecure protocols and DNS resolver configurations introduce identifiable security gaps. Determine whether IDPS-capable controls are scoped and whether DNS query logging and recursive resolver settings are assessed against stated standards.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where active policy definitions are currently missing or disabled to audit public network access on PaaS services across subscriptions (App Service, Storage, SQL, Event Hubs, Service Bus, Key Vault, Cosmos DB)
- Which resource groups or subscriptions lack policy-driven enforcement for private endpoint requirements across in-scope NS-2 service types
- Where TLS minimum version policy assignments are absent or set to non-compliant effect modes across App Service, API Management, and database service tiers
- Which hub VNets are missing Azure Firewall, DDoS Protection Standard, or WAF policy enforcement mechanisms

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding network security alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated network security gaps are responsible for driving down the overall current scoring metric.

---

## Feature 2 — Identity Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-IM] Identity Management — MCSB v2 |
| **Tags** | MCSB-v2; IM; azure-infra-sec; security-gap |
| **Priority** | 1 |

**Title**: Security Domain #2: Identity Management (IM) Baselines

**Description**:
This feature establishes identity management baseline controls to remediate the current % of Defender Secure Score Baseline and close critical identity and access audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where identity provider centralization, application identity lifecycle governance, authentication strength coverage, and conditional access policy scope deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (8 v2 controls, 5 v3 resource stories):
- IM-1 Use Centralized Identity and Authentication System [AD DS]
- IM-2 Protect Identity and Authentication Systems [v2]
- IM-3 Manage Application Identities Securely and Automatically [Bot Service, Universal Print]
- IM-4 Authenticate Server and Services [Attestation, Trusted Hardware Identity Management]
- IM-5 Use Single Sign-On (SSO) for Application Access [API Management]
- IM-6 Use Strong Authentication Controls [v2]
- IM-7 Restrict Resource Access Based on Conditions [Spatial Anchors]
- IM-8 Restrict the Exposure of Credential and Secrets [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Centralized Identity and Application Identity Coverage (IM-1, IM-3, IM-5): Assess whether Entra ID is consistently configured as the sole identity provider across all in-scope subscriptions and whether hybrid identity synchronization via AD DS reflects current organizational structure. Identify application identities — including Bot Service workloads, Universal Print resources, and API Management instances — that use client secrets or credentials rather than managed identity or federated identity mechanisms.
- AC-2 Authentication Strength and Conditional Access Scope Assessment (IM-2, IM-4, IM-6, IM-7): Assess whether Conditional Access policies are defined to enforce MFA, compliant device state, and risk-based sign-in controls for all user and service principal authentication paths in scope. Evaluate whether hardware attestation services and Trusted Hardware Identity Management resources are configured to authenticate service identities against a trusted hardware root, and determine which Spatial Anchors and mixed-reality resource access paths lack defined conditional access policy coverage.
- AC-3 Credential and Secret Exposure Assessment (IM-8): Assess whether service principals and application registrations in scope hold active client secrets beyond defined expiry thresholds or without documented justification. Identify credential exposure risk patterns — including long-lived secrets, multi-tenant application credentials, and unrotated certificates — that indicate gaps in the secret lifecycle governance posture.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where active policy definitions are currently missing or disabled to audit managed identity adoption across Function Apps, App Service, and API Management instances
- Which subscriptions lack policy-driven auditing for guest account permissions (owner, contributor, reader) and custom RBAC role proliferation
- Where multi-factor authentication enforcement policies are absent or set to non-compliant effect modes for accounts with elevated permissions

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding identity management alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated identity management gaps are responsible for driving down the overall current scoring metric.

---

## Feature 3 — Privileged Access

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-PA] Privileged Access — MCSB v2 |
| **Tags** | MCSB-v2; PA; azure-infra-sec; security-gap |
| **Priority** | 1 |

**Title**: Security Domain #3: Privileged Access (PA) Baselines

**Description**:
This feature establishes strict privileged access controls to remediate the current % of Defender Secure Score Baseline and close critical administration audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where standing privileges, un-isolated control planes and un-reviewed entitlement lifecycles deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (8 v2 controls, 4 v3 resource stories):
- PA-1 Separate and Limit Highly Privileged Users [v2]
- PA-2 Avoid Standing Access for User Accounts and Permissions [Automation]
- PA-3 Manage Lifecycle of Identities and Entitlements [v2]
- PA-4 Review and Reconcile User Access Regularly [v2]
- PA-5 Set Up Emergency Access [v2]
- PA-6 Use Privileged Access Workstations [Cloud Shell]
- PA-7 Follow Just Enough Administration (Least Privilege) Principle [Lighthouse]
- PA-8 Choose Approval Process for Microsoft Support Access [Customer Lockbox]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Standing Privilege Discovery (PA-1, PA-2, PA-6): Assess whether permanent Owner, Contributor, and User Access Administrator role assignments exist outside of Azure PIM activation workflows at subscription and management group scope. Identify accounts — including Automation service principals and Cloud Shell sessions — that hold standing privileged access without time-bound activation or approval requirements.
- AC-2 Entitlement Lifecycle and Access Review Assessment (PA-3, PA-4): Assess whether access review cycles are configured and actively completing for all privileged Entra ID PIM role assignments across subscriptions in scope. Identify entitlements lacking documented justification, defined expiry periods, or designated ownership accountability that indicate unreviewed lifecycle drift.
- AC-3 Emergency Access and Support Approval Coverage (PA-5, PA-7, PA-8): Evaluate whether break-glass emergency access accounts are provisioned, monitored for usage anomalies, and appropriately scoped outside standard Conditional Access enforcement boundaries. Determine whether Customer Lockbox is enabled for Microsoft support access scenarios and whether Lighthouse delegated administration assignments are scoped with just-enough-administration principles.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where active policy definitions are currently missing or disabled to audit permanent role assignment outside of Azure PIM
- Which resource groups or subscriptions lack policy-driven enforcement mechanisms for multi-tenant administrative tracking
- Where deprecated account and custom RBAC role usage policies are absent or not enforcing across subscription scopes

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding identity and privilege alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated privileged access gaps are responsible for driving down the overall current scoring metric.

---

## Feature 4 — Data Protection

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-DP] Data Protection — MCSB v2 |
| **Tags** | MCSB-v2; DP; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #4: Data Protection (DP) Baselines

**Description**:
This feature establishes data protection baseline controls to remediate the current % of Defender Secure Score Baseline and close critical data security audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where data classification coverage gaps, inconsistent encryption at-rest and in-transit policy enforcement, unreviewed key management ownership, and certificate lifecycle visibility deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (8 v2 controls, 28 v3 resource stories):
- DP-1 Discover, Classify, and Label Sensitive Data [Information Protection, Purview, Data Share]
- DP-2 Monitor Anomalies and Threats Targeting Sensitive Data [Data Explorer, OpenAI, Intelligent Recommendations]
- DP-3 Encrypt Sensitive Data in Transit [MariaDB, MySQL Flexible, PostgreSQL Flexible, Cosmos DB for PostgreSQL, Stream Analytics, Media Services]
- DP-4 Enable Data at Rest Encryption by Default [Storage, SQL, SQL IaaS, Analysis Services, App Configuration, SAP, Data Lake Analytics]
- DP-5 Use Customer-Managed Key When Required [Cosmos DB, Synapse, Data Manager for Energy, Cassandra, NetApp Files]
- DP-6 Use a Secure Key Management Process [Key Vault, Key Vault HSM, Dedicated HSM]
- DP-7 Use a Secure Certificate Management Process [v2]
- DP-8 Ensure Security of Key and Certificate Repository [Data Box]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Data Classification and Sensitivity Labeling Coverage (DP-1, DP-2): Assess whether data discovery and classification tooling via Information Protection, Purview, and Data Share has been scoped to include all storage accounts, SQL databases, and Cosmos DB instances in the environment. Identify data stores where sensitivity labels are absent, anomaly detection via Data Explorer, OpenAI, and Intelligent Recommendations services lacks baseline alerting configuration, or classification scan coverage has not been validated against the full inventory.
- AC-2 Encryption in Transit and At Rest Coverage Assessment (DP-3, DP-4, DP-7): Evaluate whether minimum TLS version policy assignments are active for MariaDB, MySQL Flexible, PostgreSQL Flexible, Cosmos DB for PostgreSQL, Stream Analytics, and Media Services instances, and whether in-transit encryption gaps exist across these data platform services. Determine which Storage, SQL, SQL IaaS, Analysis Services, App Configuration, SAP, and Data Lake Analytics resources lack platform-managed encryption at rest with documented key ownership, or have public network access enabled against stated network segmentation standards.
- AC-3 Customer-Managed Key and Key Management Process Assessment (DP-5, DP-6, DP-8): Assess whether Cosmos DB, Synapse, Data Manager for Energy, Cassandra, and NetApp Files resources designated as requiring CMK have active key vault references with defined key rotation policies and documented ownership accountability. Identify whether Key Vault, Key Vault HSM, and Dedicated HSM instances are configured with soft delete, purge protection, and private endpoint access, and determine whether Data Box transfer operations are subject to encryption lifecycle controls.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where active policy definitions are currently missing or disabled to audit public blob access, shared key access, and network firewall configuration across Storage accounts
- Which database service tiers (SQL, MariaDB, MySQL Flexible, PostgreSQL Flexible, Cosmos DB) lack TLS minimum version policy assignments or have non-compliant effect modes
- Where Key Vault instances are missing soft delete, purge protection, or private endpoint policy enforcement across subscriptions in scope
- Which data store resource types lack CMK policy assignments for resources classified as requiring customer-managed encryption

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding data protection alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated data protection gaps are responsible for driving down the overall current scoring metric.

---

## Feature 5 — Asset Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-AM] Asset Management — MCSB v2 |
| **Tags** | MCSB-v2; AM; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #5: Asset Management (AM) Baselines

**Description**:
This feature establishes asset management baseline controls to remediate the current % of Defender Secure Score Baseline and close critical resource governance audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where incomplete asset inventory coverage, inconsistent resource tagging and governance policy application, unreviewed asset lifecycle management, and unapproved resource type and application deployment patterns deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (5 v2 controls, 5 v3 resource stories):
- AM-1 Track Asset Inventory and Their Risks [Resource Graph, Migrate]
- AM-2 Use Only Approved Services [Policy]
- AM-3 Ensure Security of Asset Lifecycle Management [Resource Mover, DevTest Labs]
- AM-4 Limit Access to Asset Management [Resource Manager]
- AM-5 Use Only Approved Applications in Virtual Machine [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Asset Inventory and Risk Coverage Assessment (AM-1, AM-2): Assess whether Resource Graph queries and Azure Migrate discovery scans provide complete coverage of all resource types deployed across subscriptions and management groups in scope. Identify resource types, regions, or subscription scopes excluded from inventory tracking, and determine whether Azure Policy assignments for approved service types are active and reporting compliance across all management group levels.
- AC-2 Asset Lifecycle and Access Governance Assessment (AM-3, AM-4, AM-5): Evaluate whether Resource Mover and DevTest Labs resources are subject to defined lifecycle governance controls, including documented decommission procedures and ownership accountability for resources undergoing migration or transition. Identify Resource Manager-level access control gaps — including missing resource locks on production resources, absent management group RBAC assignments, and unapproved application installations on virtual machines not covered by adaptive application controls.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where mandatory tagging policy assignments (Environment, Owner, CostCenter, DataClassification) are missing or set to audit-only effect modes at resource group or subscription scope
- Which subscriptions or management groups lack allowed resource types and allowed locations policy initiatives, permitting unapproved service and region deployments
- Where resource lock policies are absent for production-designated resource groups, leaving resources without delete or read-only protection

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding asset management alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated asset management gaps are responsible for driving down the overall current scoring metric.

---

## Feature 6 — Logging and Threat Detection

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-LT] Logging and Threat Detection — MCSB v2 |
| **Tags** | MCSB-v2; LT; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #6: Logging and Threat Detection (LT) Baselines

**Description**:
This feature establishes logging and threat detection baseline controls to remediate the current % of Defender Secure Score Baseline and close critical observability and detection audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where inconsistent diagnostic settings deployment, absent or fragmented threat detection capability coverage, unverified log centralization and cross-source correlation, and unenforced log retention and time synchronization standards deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (7 v2 controls, 2 v3 resource stories):
- LT-1 Enable Threat Detection Capabilities [Defender for Cloud]
- LT-2 Enable Threat Detection for Identity and Access Management [v2]
- LT-3 Enable Logging for Security Investigation [v2]
- LT-4 Enable Network Logging for Security Investigation [v2]
- LT-5 Centralize Security Log Management and Analysis [Sentinel, Monitor]
- LT-6 Configure Log Storage Retention [v2]
- LT-7 Use Approved Time Synchronization Sources [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Threat Detection Capability and Diagnostic Settings Coverage (LT-1, LT-2, LT-3): Assess whether Defender for Cloud plans are enabled across all relevant resource types in scope and whether threat detection capabilities are active for identity and access management workloads. Identify subscriptions where diagnostic settings are absent or not forwarding to a designated Log Analytics workspace, and determine which resource types lack policy-driven deployment of diagnostic configurations.
- AC-2 Network Logging and Log Retention Assessment (LT-4, LT-6, LT-7): Evaluate whether NSG flow logs, Azure Firewall diagnostic logs, and Traffic Analytics are configured for network resources in scope, and whether network-level logging gaps introduce visibility deficiencies for security investigation purposes. Determine whether Log Analytics workspace retention settings meet defined standards for interactive and archive retention periods, and assess whether time synchronization sources for resources in scope are validated against approved NTP configurations.
- AC-3 Centralized Security Log Management Assessment (LT-5): Assess whether Sentinel and Azure Monitor are configured as the centralized log management and analysis platform across all subscriptions in scope, and whether data connectors are active for all in-scope log sources. Identify analytics rule gaps and data connector coverage deficiencies that limit cross-source correlation and reduce the effectiveness of threat detection across MCSB v2 security domains.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where diagnostic settings DeployIfNotExists policy assignments are missing or in audit-only mode for resource types in scope, leaving log forwarding to Log Analytics unverified
- Which subscriptions lack Azure Defender plan enablement policies for Servers, Storage, SQL, Containers, App Service, and Key Vault
- Where NSG flow log policy assignments are absent or non-compliant for network security groups across subscriptions in scope

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding logging and threat detection alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated logging and threat detection gaps are responsible for driving down the overall current scoring metric.

---

## Feature 7 — Incident Response

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-IR] Incident Response — MCSB v2 |
| **Tags** | MCSB-v2; IR; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #7: Incident Response (IR) Baselines

**Description**:
This feature establishes incident response baseline controls to remediate the current % of Defender Secure Score Baseline and close critical incident preparedness audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where undocumented incident response plan coverage for Azure-specific scenarios, incomplete security notification configuration, unvalidated incident detection and alert quality, and limited investigation tooling readiness deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (4 v2 controls):
- IR-1 Establish an Incident Response Plan and Handling [v2]
- IR-2 Preparation — Setup Incident Notification [v2]
- IR-3 Detection and Analysis — Create Incidents Based on High Quality Alerts [v2]
- IR-4 Detection and Analysis — Investigate an Incident [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 IR Plan and Notification Readiness Assessment (IR-1, IR-2): Assess whether a documented incident response plan exists for Azure-specific threat scenarios — including ransomware, account compromise, and data exfiltration — and whether the plan covers defined roles, escalation paths, and communication procedures aligned to organizational standards. Determine whether security contact configuration in Defender for Cloud is current and whether alert notification action groups are configured to route High and Critical severity alerts to the appropriate response team.
- AC-2 Detection Quality and Investigation Readiness Assessment (IR-3, IR-4): Evaluate whether Sentinel analytics rules are generating high-fidelity incidents with appropriate severity classification, and whether false positive rates for active analytics rules indicate signal quality gaps that could delay incident triage. Identify whether investigation tooling — including UEBA, Sentinel investigation graph, and Live Response capabilities — is configured and accessible for incident analysts, and assess whether investigation runbooks exist for priority threat scenarios.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where security contact email policy assignments are absent or non-compliant across subscriptions in scope
- Which subscriptions lack email notification policy enforcement for high severity Defender for Cloud alerts and owner-level alert routing

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding incident response readiness alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated incident response gaps are responsible for driving down the overall current scoring metric.

---

## Feature 8 — Posture and Vulnerability Management

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-PV] Posture and Vulnerability Management — MCSB v2 |
| **Tags** | MCSB-v2; PV; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #8: Posture and Vulnerability Management (PV) Baselines

**Description**:
This feature establishes posture and vulnerability management baseline controls to remediate the current % of Defender Secure Score Baseline and close critical vulnerability assessment and configuration audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where incomplete automated vulnerability scanning coverage for compute and container workloads, unverified OS patch management cadence and compliance, unenforced secure configuration baselines, and absent formal red team validation cadence deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (7 v2 controls, 2 v3 resource stories):
- PV-1 Run Automated Vulnerability Scans [Defender for Cloud]
- PV-2 Run Automated OS Patch Management [v2]
- PV-3 Establish Secure Configurations for Compute Resources [v2]
- PV-4 Audit and Enforce Secure Configurations [v2]
- PV-5 Perform Vulnerability Assessments [Advisor]
- PV-6 Rapidly and Automatically Remediate Vulnerabilities [v2]
- PV-7 Conduct Regular Red Team Operations [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Automated Vulnerability Scan and Posture Assessment (PV-1, PV-5): Assess whether Defender for Cloud and Advisor are enabled and actively generating vulnerability assessment findings for virtual machines, container images, and other compute resources across all subscriptions in scope. Identify resources where vulnerability assessment solution deployment is absent, Defender for Cloud Secure Score recommendations remain unacknowledged, or Advisor security recommendations lack assigned ownership and remediation timelines.
- AC-2 OS Patch Management and Secure Configuration Compliance (PV-2, PV-3, PV-4): Evaluate whether OS patch management processes are configured to assess patch compliance state for virtual machines and other compute resources, and whether system update policy assignments are active and reporting non-compliant resources. Determine which compute resources lack defined secure configuration baselines or where configuration assessment tooling — including machine configuration policies and Defender for Cloud compute recommendations — has not been validated against stated hardening standards.
- AC-3 Vulnerability Remediation Cadence and Red Team Coverage Assessment (PV-6, PV-7): Assess whether vulnerability remediation workflows are defined for critical and high-severity findings identified through automated scanning, and identify findings that have exceeded organization-defined remediation timeframes without documented risk acceptance. Determine whether a formal red team operations cadence exists to validate the effectiveness of implemented controls, and evaluate whether Defender attack path analysis findings are reviewed to supplement external red team coverage.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where vulnerability assessment solution policy assignments are missing or set to audit-only for virtual machines and virtual machine scale sets across subscriptions in scope
- Which compute resource types lack system update policy enforcement, resulting in untracked patch compliance state for OS-level vulnerabilities
- Where secure configuration baseline policy assignments are absent or not remediating non-compliant machine configuration settings across in-scope compute resources

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding posture and vulnerability management alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated posture and vulnerability management gaps are responsible for driving down the overall current scoring metric.

---

## Feature 9 — Endpoint Security

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-ES] Endpoint Security — MCSB v2 |
| **Tags** | MCSB-v2; ES; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #9: Endpoint Security (ES) Baselines

**Description**:
This feature establishes endpoint security baseline controls to remediate the current % of Defender Secure Score Baseline and close critical endpoint protection audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where incomplete EDR sensor deployment across VM and container workloads, unreviewed antimalware exclusion governance, absent container image security scan coverage, and IoT and OT device endpoint visibility gaps deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (3 v2 controls, 14 v3 resource stories):
- ES-1 Use Endpoint Detection and Response (EDR) [Virtual Machines Linux, Virtual Machines Windows, Virtual Machine Scale Sets, Arc Servers, Arc Kubernetes]
- ES-2 Use Modern Anti-Malware Software [v2]
- ES-3 Ensure Anti-Malware Software and Signatures Updated [Container Registry, Container Instances, AKS, HCI Kubernetes, ARO, Defender for IoT, IoT Hub, IoT Central, Sphere]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 EDR Coverage and Deployment Assessment (ES-1): Assess whether Microsoft Defender for Endpoint is deployed and reporting telemetry for all Virtual Machines (Linux and Windows), Virtual Machine Scale Sets, Arc-enabled Servers, and Arc-enabled Kubernetes clusters in scope. Identify compute resources where EDR sensor deployment is absent, MDE health status is degraded, or endpoint detection and response capabilities have not been validated against organizational deployment standards.
- AC-2 Antimalware Governance Assessment (ES-2): Evaluate whether antimalware policies and exclusion lists for in-scope compute resources are documented, reviewed on a defined cadence, and scoped to minimum necessary exclusions. Determine whether antimalware health reports indicate coverage gaps, stale signature states, or exclusion configurations that may reduce detection efficacy across the endpoint population.
- AC-3 Container, IoT, and OT Endpoint Security Posture Assessment (ES-3): Assess whether container image security scanning is configured for Container Registry, Container Instances, AKS, HCI Kubernetes, and ARO resources, and identify images where known vulnerability findings have not been addressed prior to production deployment. Evaluate whether Defender for IoT, IoT Hub, IoT Central, and Sphere device inventories are complete and whether OT and IoT endpoint security coverage extends to all connected device populations in scope.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where Microsoft Defender for Endpoint agent deployment policy assignments are missing or non-compliant for Virtual Machines, Virtual Machine Scale Sets, and Arc-enabled Servers
- Which container registry and AKS cluster resources lack Defender for Containers policy enablement, leaving container image scanning and runtime threat detection unconfigured
- Where endpoint protection policy assignments are absent or in audit-only mode for compute resource types in scope

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding endpoint security alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated endpoint security gaps are responsible for driving down the overall current scoring metric.

---

## Feature 10 — Backup and Recovery

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-BR] Backup and Recovery — MCSB v2 |
| **Tags** | MCSB-v2; BR; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #10: Backup and Recovery (BR) Baselines

**Description**:
This feature establishes backup and recovery baseline controls to remediate the current % of Defender Secure Score Baseline and close critical data resilience and continuity audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where incomplete backup policy coverage across production workloads, unverified vault protection configuration and geo-redundancy, absent backup monitoring and alerting validation, and untested restore and disaster recovery readiness deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (4 v2 controls, 2 v3 resource stories):
- BR-1 Ensure Regular Automated Backups [Backup]
- BR-2 Protect Backup and Recovery Data [v2]
- BR-3 Monitor Backups [v2]
- BR-4 Regularly Test Backup [Site Recovery]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Backup Coverage and Vault Configuration Assessment (BR-1, BR-2): Assess whether Azure Backup policies are configured for all production virtual machines, SQL databases, blob storage, and file share resources in scope, and whether Recovery Services vaults are configured with geo-redundant storage and private endpoint access. Identify production workloads without an active backup policy assignment, vaults where immutable vault, soft delete, or CMK encryption configuration has not been validated, and subscriptions where backup operator RBAC separation has not been assessed.
- AC-2 Backup Monitoring and Restore Readiness Assessment (BR-3, BR-4): Evaluate whether backup monitoring alerts are configured to notify the appropriate team on backup job failure, and whether Site Recovery replication is configured for production workloads with defined RTO and RPO targets. Determine whether restore testing has been performed for in-scope workloads within the defined cadence, and assess whether disaster recovery failover procedures are documented and have been validated through tabletop or technical DR exercises.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where Azure Backup policy assignments are absent or non-compliant for virtual machines, SQL databases, and file storage resources across subscriptions in scope
- Which Recovery Services vaults lack geo-redundant storage configuration or private link enforcement policy assignments
- Where geo-redundant backup policy assignments are missing for MySQL Flexible, PostgreSQL Flexible, and SQL database services in scope

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding backup and recovery alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated backup and recovery gaps are responsible for driving down the overall current scoring metric.

---

## Feature 11 — DevOps Security

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-DS] DevOps Security — MCSB v2 |
| **Tags** | MCSB-v2; DS; azure-infra-sec; security-gap |
| **Priority** | 3 |

**Title**: Security Domain #11: DevOps Security (DS) Baselines

**Description**:
This feature establishes DevOps security baseline controls to remediate the current % of Defender Secure Score Baseline and close critical secure development lifecycle audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where absent threat modeling integration in the design phase, unverified software supply chain security practices, insufficient DevOps infrastructure security posture, and missing static and dynamic application security testing coverage in CI/CD pipelines deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (6 v2 controls):
- DS-1 Conduct Threat Modeling [v2]
- DS-2 Ensure Software Supply Chain Security [v2]
- DS-3 Secure DevOps Infrastructure [v2]
- DS-4 Integrate Static Application Security Testing [v2]
- DS-5 Integrate Dynamic Application Security Testing [v2]
- DS-6 Enforce Security of Workload Throughout DevOps Lifecycle [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Threat Modeling and Supply Chain Security Assessment (DS-1, DS-2): Assess whether threat modeling practices are integrated into the design phase for in-scope workloads, and whether threat models for priority systems are documented and reviewed against current architecture. Evaluate whether software supply chain security controls — including dependency scanning, SBOM generation, container image signing, and software composition analysis — are configured for CI/CD pipelines associated with in-scope services.
- AC-2 DevOps Infrastructure Security Posture Assessment (DS-3, DS-6): Assess whether Azure DevOps and GitHub repository security configurations — including branch protection policies, secret scanning enablement, and service connection credential management — are in place and consistent with organizational security standards. Determine whether workload security controls are applied throughout the DevOps lifecycle, including pipeline access controls, IaC scanning gates, and service connection authentication patterns that eliminate long-lived credential exposure.
- AC-3 SAST and DAST Coverage Assessment (DS-4, DS-5): Evaluate whether static application security testing tools are integrated into CI/CD pipelines for in-scope repositories, and identify repositories where SAST coverage is absent or where findings above defined severity thresholds are not blocking merge operations. Determine whether dynamic application security testing is configured for internet-facing services in scope, and assess whether DAST scan results are reviewed and tracked against defined remediation criteria.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where Defender for DevOps connector policy assignments are absent or not configured to assess Azure DevOps and GitHub repository security posture across subscriptions in scope
- Which subscriptions lack Defender for DevOps enablement, resulting in no code-to-cloud security visibility for IaC misconfiguration, secret scan, and dependency scan findings

Note: DS controls are cross-cutting DevOps security practices — native Azure Policy definitions do not cover DS-1, DS-5, or pipeline-level security gates. Assessment coverage for these controls relies on Defender for DevOps and manual process review.

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding DevOps security alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated DevOps security gaps — including IaC misconfigurations, exposed secrets, and supply chain findings surfaced through Defender for DevOps — are responsible for driving down the overall current scoring metric.

---

## Feature 12 — Governance and Strategy

| Field | Value |
|---|---|
| **Work Item Type** | Feature |
| **Title** | [SEC-GS] Governance and Strategy — MCSB v2 |
| **Tags** | MCSB-v2; GS; azure-infra-sec; security-gap |
| **Priority** | 2 |

**Title**: Security Domain #12: Governance and Strategy (GS) Baselines

**Description**:
This feature establishes governance and strategy baseline controls to remediate the current % of Defender Secure Score Baseline and close critical security governance and accountability audit findings. In alignment with the Microsoft Cloud Security Benchmark (MCSB) v2 domain, the core effort here is to audit and identify where undefined security domain roles and accountability structures, unassigned MCSB policy initiative and regulatory compliance tracking, undocumented cross-domain security strategy coverage, and unverified governance posture management and Secure Score visibility deviate from stated standards. This feature assesses the configuration settings, policy definitions and current-state assignments of the following:

**Controls List** (10 v2 controls, 3 v3 resource stories):
- GS-1 Align Organization Roles, Responsibilities, and Accountabilities [Cost Management]
- GS-2 Define and Implement Enterprise Segmentation Strategy [v2]
- GS-3 Define and Implement Data Protection Strategy [v2]
- GS-4 Define and Implement Network Security Strategy [v2]
- GS-5 Define and Implement Security Posture Management Strategy [Policy]
- GS-6 Define and Implement Identity and Privileged Access Strategy [v2]
- GS-7 Define and Implement Logging, Threat Detection and IR Strategy [v2]
- GS-8 Define and Implement Backup and Recovery Strategy [Managed Applications]
- GS-9 Define and Implement Endpoint Security Strategy [v2]
- GS-10 Define and Implement DevOps Security Strategy [v2]

**Intended Business Outcome**: TBC

**Success Measures**:
- AC-1 Organizational Roles, Accountability, and Cost Governance Assessment (GS-1): Assess whether security domain ownership and accountability assignments are documented and current for all 12 MCSB v2 domains in scope, and whether Cost Management resource tagging and budget governance controls align with defined organizational accountability structures. Identify domains where security domain ownership is unassigned, cost allocation tagging is absent, or financial governance visibility does not support security investment tracking.
- AC-2 Security Posture Management and Policy Initiative Assessment (GS-5): Evaluate whether the Microsoft Cloud Security Benchmark policy initiative is assigned at management group scope and actively reporting compliance state across subscriptions in scope. Assess whether Azure Policy assignments for security posture governance — including the Regulatory Compliance dashboard configuration and MCSB-aligned policy definitions — are enabled and reviewed on a defined cadence, and determine which Managed Applications resource policies are missing from the governance scope.
- AC-3 Cross-Domain Strategy Documentation Coverage Assessment (GS-2, GS-3, GS-4, GS-6, GS-7, GS-8, GS-9, GS-10): Assess whether documented security strategy artifacts exist for enterprise segmentation, data protection, network security, identity and privileged access, logging and threat detection, backup and recovery, endpoint security, and DevOps security domains. Identify strategies that are absent, last reviewed beyond defined review cadence, or represent informal tribal knowledge not aligned to stated MCSB v2 standards.

**Release Notes**: N/A

**Architectural and Technical Outcomes**:

### Azure Policy Assessment (JSON export sync)
The automated analysis engine parses the comprehensive Azure Policy JSON export to check for compliance gaps. This feature evaluates:
- Where the Microsoft Cloud Security Benchmark initiative assignment is absent at management group scope or configured with effect modes that do not surface compliance state in the Regulatory Compliance dashboard
- Which subscriptions or management groups lack policy assignments for custom RBAC role auditing, resource group ownership tagging, and security contact enforcement
- Where Azure Policy assignments for Managed Applications governance are missing or not scoped to cover marketplace and internal managed application deployments

### Microsoft Defender for Cloud Variance Mapping (JSON recommendation sync)
The evaluation workflow correlates outstanding governance and strategy alerts from the incoming Defender JSON recommendation arrays. The tool maps these vulnerabilities directly to the Secure Score ledger to pinpoint which unremediated governance and strategy gaps are responsible for driving down the overall current scoring metric.

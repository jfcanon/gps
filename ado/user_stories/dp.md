# Data Protection (DP) — User Stories

29 user stories: 28 combined (v2+v3, one per resource) + 1 pure v2.
Phase 18 — ADO format with policy hyperlinks. Assessment tone. Task Source removed.
Parent Feature: [SEC-DP] Data Protection — MCSB v2

---

## [SEC-DP] Data Protection — 8 Controls, 29 Stories

### 1 Discover, Classify, and Label Sensitive Data [3 combined]

**[SEC-1] Discover, Classify, and Label Sensitive Data: Information Protection**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Microsoft Information Protection sensitivity label configuration — label taxonomy coverage (Public/Internal/Confidential/Restricted), auto-labeling policy coverage for known sensitive data patterns, and label inheritance enforcement for data copied to Azure Storage — so that DP-1 gaps where sensitive data lacks appropriate classification or labeling automation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for data classification and sensitivity labeling controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Microsoft Purview sensitivity label reports and manual auto-labeling policy audit.

**Acceptance Criteria:**
- Information Protection DP-1 configuration assessed against MCSB baseline and environments missing label taxonomy coverage, auto-labeling policy gaps, or label inheritance failures for Azure Storage data identified.
- Azure Policy coverage for data classification controls evaluated; built-ins absent for this control — assessment relies on Microsoft Information Protection admin center and sensitivity label analytics manual audit.
- Gap findings documented with remediation scope and affected label policies, auto-labeling scopes, and storage label inheritance configurations noted.

---

**[SEC-1] Discover, Classify, and Label Sensitive Data: Purview**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Microsoft Purview data governance posture — data catalog scan coverage across Storage, SQL, Synapse, and ADLS, classification rule configuration for sensitive data patterns, sensitive data discovery report completeness, DLP policy enforcement status, and Insider Risk Management integration — so that DP-1 gaps in sensitive data discovery and automated classification coverage are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Purview data catalog scanning or DLP policy enforcement in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Purview Data Map scan results and compliance portal manual audit.

**Acceptance Criteria:**
- Purview DP-1 configuration assessed against MCSB baseline and data sources without active catalog scans, missing classification rules for sensitive patterns, or absent DLP policy enforcement identified.
- Azure Policy coverage for Purview data governance controls evaluated; built-ins absent for this control — assessment relies on Purview Data Map scan coverage and compliance portal reports.
- Gap findings documented with remediation scope and affected data sources, classification rules, DLP policies, and Insider Risk Management configurations noted.

---

**[SEC-1] Discover, Classify, and Label Sensitive Data: Data Share**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Share data classification and access control posture — sensitivity classification of shared datasets before sharing, absence of Confidential/Restricted data in unapproved shares, recipient identity validation process, snapshot access review cadence, and shared dataset sensitivity label coverage — so that DP-1 gaps where sensitive data is shared without appropriate classification or recipient validation are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Data Share classification controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on Data Share invitation audit and dataset sensitivity label manual review.

**Acceptance Criteria:**
- Data Share DP-1 configuration assessed against MCSB baseline and active shares containing Confidential/Restricted datasets without approval documentation, or missing recipient identity validation, identified.
- Azure Policy coverage for Data Share classification controls evaluated; built-ins absent for this control — assessment relies on Data Share invitation log and sensitivity label manual audit.
- Gap findings documented with remediation scope and affected share invitations, shared datasets, and snapshot access review configurations noted.

---

### 2 Monitor Anomalies and Threats Targeting Sensitive Data [3 combined]

**[SEC-2] Monitor Anomalies and Threats Targeting Sensitive Data: Data Explorer**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Explorer anomalous access monitoring configuration — Defender for Databases enablement for anomalous query detection, row-level security policy coverage on sensitive tables, query audit log routing to Log Analytics, and access pattern baseline documentation — so that DP-2 gaps in sensitive data threat monitoring and behavioral anomaly detection for the Data Explorer estate are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Data Explorer clusters should enable disk encryption"](https://www.azadvertizer.net/azpolicyadvertizer.html) (security-adjacent — no anomaly monitoring-specific built-in confirmed for Data Explorer in MCSB v2 preview).

**Acceptance Criteria:**
- Data Explorer DP-2 configuration assessed against MCSB baseline and clusters without Defender for Databases enablement, missing row-level security on sensitive tables, or absent query audit log routing identified.
- Azure Policy coverage for Data Explorer threat monitoring controls evaluated; anomaly monitoring built-ins absent — assessment relies on Defender for Databases and Log Analytics diagnostic settings manual audit.
- Gap findings documented with remediation scope and affected Data Explorer cluster, table-level security, and audit log routing configurations noted.

---

**[SEC-2] Monitor Anomalies and Threats Targeting Sensitive Data: OpenAI**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure OpenAI sensitive data protection posture — content filtering policy coverage across all harm categories, input/output logging routing to Log Analytics for data exfiltration monitoring, managed identity authentication status replacing API key usage in code, and diagnostic log configuration — so that DP-2 gaps in AI service data threat monitoring and credential hygiene are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure OpenAI should use private link"](https://www.azadvertizer.net/azpolicyadvertizer.html) (network isolation adjacent — no content filtering or logging-specific built-in confirmed for OpenAI in MCSB v2 preview; verify against current policy list).

**Acceptance Criteria:**
- Azure OpenAI DP-2 configuration assessed against MCSB baseline and deployments without content filtering enabled, missing input/output logging to Log Analytics, or using API keys in application code identified.
- Azure Policy coverage for OpenAI threat monitoring controls evaluated; gaps in built-in policy automation noted — assessment relies on Azure OpenAI Studio content filter settings and diagnostic log configuration manual audit.
- Gap findings documented with remediation scope and affected OpenAI resource, content filter policy, logging configuration, and authentication method instances noted.

---

**[SEC-2] Monitor Anomalies and Threats Targeting Sensitive Data: Intelligent Recommendations**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Intelligent Recommendations data access monitoring posture — audit log coverage for data access events, managed identity assignment for model training data access, absence of PII in recommendation metadata, and anomalous recommendation pattern monitoring configuration — so that DP-2 gaps in sensitive data access visibility for recommendation service workloads are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Intelligent Recommendations in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on managed identity configuration and diagnostic log manual audit.

**Acceptance Criteria:**
- Intelligent Recommendations DP-2 configuration assessed against MCSB baseline and instances without managed identity for training data access, missing audit logging, or with PII present in recommendation metadata identified.
- Azure Policy coverage for Intelligent Recommendations controls evaluated; built-ins absent for this resource — assessment relies on managed identity assignment and diagnostic log configuration manual audit.
- Gap findings documented with remediation scope and affected Intelligent Recommendations account, training data access, and audit log configurations noted.

---

### 3 Encrypt Sensitive Data in Transit [6 combined]

**[SEC-3] Encrypt Sensitive Data in Transit: Database for MariaDB**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Database for MariaDB transit encryption configuration — SSL enforcement parameter status (ssl_enforce_enabled=ON), TLS 1.2 minimum version setting, non-SSL connection disable status, and client certificate pinning configuration — so that DP-3 gaps where MariaDB client connections traverse unencrypted channels or operate below minimum TLS version requirements are identified. Key Azure Policy built-ins applicable: ⚠️ ["Enforce SSL connection should be enabled for MariaDB server"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list; note MariaDB single server is on deprecation path).

**Acceptance Criteria:**
- Database for MariaDB DP-3 configuration assessed against MCSB baseline and servers with SSL enforcement disabled or TLS version below 1.2 minimum identified.
- Azure Policy compliance evaluated for SSL enforcement controls applicable to Azure Database for MariaDB; ⚠️ "Enforce SSL connection should be enabled for MariaDB server" flagged for display name verification.
- Gap findings documented with remediation scope and affected MariaDB server and client connection configuration instances noted.

---

**[SEC-3] Encrypt Sensitive Data in Transit: Database for MySQL Flexible Server**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Database for MySQL Flexible Server transit encryption configuration — TLS minimum version parameter (1.2+), unencrypted connection disable status, HTTPS-only connection string enforcement in application configurations, and TLS parameter audit coverage — so that DP-3 gaps where MySQL Flexible Server connections operate below minimum TLS version requirements are identified. Key Azure Policy built-ins applicable: ⚠️ ["SSL should be enabled for Azure Database for MySQL flexible server"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name; Flexible Server policies differ from Single Server).

**Acceptance Criteria:**
- Database for MySQL Flexible Server DP-3 configuration assessed against MCSB baseline and servers with TLS version below 1.2 or with unencrypted connections permitted identified.
- Azure Policy compliance evaluated for SSL and TLS minimum version controls applicable to MySQL Flexible Server; ⚠️ flag for display name verification against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected MySQL Flexible Server parameter and application connection string configurations noted.

---

**[SEC-3] Encrypt Sensitive Data in Transit: Database for PostgreSQL Flexible Server**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Database for PostgreSQL Flexible Server transit encryption configuration — TLS minimum version enforcement, ssl_mode=REQUIRE status for all client connections, plaintext connection disable status, and client-side certificate validation configuration — so that DP-3 gaps where PostgreSQL Flexible Server connections operate over unencrypted or insufficiently authenticated channels are identified. Key Azure Policy built-ins applicable: ⚠️ ["SSL should be enabled for Azure Database for PostgreSQL flexible server"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name; Flexible Server policies differ from Single Server).

**Acceptance Criteria:**
- Database for PostgreSQL Flexible Server DP-3 configuration assessed against MCSB baseline and servers with plaintext connections permitted or ssl_mode below REQUIRE identified.
- Azure Policy compliance evaluated for SSL and TLS minimum version controls applicable to PostgreSQL Flexible Server; ⚠️ flag for display name verification against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected PostgreSQL Flexible Server parameter and client connection configurations noted.

---

**[SEC-3] Encrypt Sensitive Data in Transit: Cosmos DB for PostgreSQL**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cosmos DB for PostgreSQL transit encryption configuration — TLS 1.2 enforcement status, SSL required setting for all client connections, certificate validation configuration, and absence of plaintext PostgreSQL wire protocol connections — so that DP-3 gaps where Cosmos DB for PostgreSQL client traffic traverses unencrypted paths are identified. Key Azure Policy built-ins applicable: ⚠️ ["SSL should be enabled on Cosmos DB for PostgreSQL"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Cosmos DB for PostgreSQL DP-3 configuration assessed against MCSB baseline and clusters with SSL enforcement disabled or plaintext PostgreSQL connections permitted identified.
- Azure Policy compliance evaluated for SSL enforcement controls applicable to Cosmos DB for PostgreSQL; built-in display name to be verified against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected Cosmos DB for PostgreSQL cluster and client connection configurations noted.

---

**[SEC-3] Encrypt Sensitive Data in Transit: Stream Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Stream Analytics transit encryption posture — TLS enforcement across all configured input and output connections (Event Hub, Service Bus, SQL, Storage), managed identity authentication for source and sink connectivity, and absence of plaintext credentials in job configuration — so that DP-3 gaps where streaming pipeline data traverses unencrypted channels or relies on static credentials are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Stream Analytics transit encryption controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on job input/output connection TLS settings and credential configuration manual audit.

**Acceptance Criteria:**
- Stream Analytics DP-3 configuration assessed against MCSB baseline and jobs with non-TLS input/output connections, plaintext credentials in job config, or missing managed identity authentication identified.
- Azure Policy coverage for Stream Analytics transit encryption controls evaluated; built-ins absent for this resource — assessment relies on job input/output connection settings and managed identity manual audit.
- Gap findings documented with remediation scope and affected Stream Analytics job, input, and output connection configurations noted.

---

**[SEC-3] Encrypt Sensitive Data in Transit: Media Services**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Media Services transit encryption posture — HTTPS-only streaming delivery policy status, DRM coverage (PlayReady/Widevine/FairPlay) for encrypted content protection, managed identity assignment for storage account access, and TLS enforcement for live encoder ingest connections — so that DP-3 gaps where media content is delivered or ingested over unprotected transport channels are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Media Services transit encryption controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on streaming policy configuration and live event ingest settings manual audit.

**Acceptance Criteria:**
- Media Services DP-3 configuration assessed against MCSB baseline and accounts with HTTP streaming delivery, missing DRM for protected content, or live encoder ingest without TLS identified.
- Azure Policy coverage for Media Services transit encryption controls evaluated; built-ins absent for this resource — assessment relies on streaming policy, content key policy, and live event configuration manual audit.
- Gap findings documented with remediation scope and affected Media Services account, streaming policy, and live event configurations noted.

---

### 4 Enable Data at Rest Encryption by Default [7 combined]

**[SEC-4] Enable Data at Rest Encryption by Default: Storage**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Storage encryption at rest configuration — AES-256 platform-managed key status, CMK adoption for Confidential/Restricted data tiers, allow-blob-public-access disabled status, infrastructure encryption enablement, and immutability policy coverage for compliance-tier containers — so that DP-4 gaps in storage data protection configuration and public exposure are identified. Key Azure Policy built-ins applicable: ["Secure transfer to storage accounts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference), ⚠️ ["Storage accounts should use customer-managed key for encryption"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name for CMK policy).

**Acceptance Criteria:**
- Storage DP-4 configuration assessed against MCSB baseline and accounts with public blob access enabled, missing infrastructure encryption for sensitive tiers, or lacking CMK for Confidential data identified.
- Azure Policy compliance evaluated for: ["Secure transfer to storage accounts should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) and applicable CMK enforcement controls.
- Gap findings documented with remediation scope and affected storage account, container, and encryption configuration instances noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: SQL**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure SQL Database encryption at rest configuration — Transparent Data Encryption enablement status, TDE key type assessment (PMK versus CMK) for classified databases, SQL Auditing routing to Log Analytics, Always Encrypted usage for highly sensitive columns, and database export encryption policy — so that DP-4 gaps in SQL database data protection and audit coverage are identified. Key Azure Policy built-ins applicable: ["Transparent data encryption on SQL databases should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- SQL Database DP-4 configuration assessed against MCSB baseline and databases with TDE disabled, SQL Auditing not routing to Log Analytics, or highly sensitive columns without Always Encrypted identified.
- Azure Policy compliance evaluated for: ["Transparent data encryption on SQL databases should be enabled"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected SQL database, TDE configuration, and audit log routing instances noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: SQL IaaS**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess SQL Server on Azure VMs encryption at rest configuration — Azure Disk Encryption or EncryptionAtHost enablement on VM operating system and data disks, TDE status on SQL databases hosted on IaaS, backup encryption coverage, and Key Vault integration for encryption key management — so that DP-4 gaps in IaaS-based SQL server data protection are identified. Key Azure Policy built-ins applicable: ["Disk encryption should be applied on virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).

**Acceptance Criteria:**
- SQL IaaS DP-4 configuration assessed against MCSB baseline and VMs without Azure Disk Encryption or EncryptionAtHost, or SQL databases without TDE enabled, identified.
- Azure Policy compliance evaluated for: ["Disk encryption should be applied on virtual machines"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference).
- Gap findings documented with remediation scope and affected VM disk encryption, SQL TDE, and backup encryption configurations noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: Analysis Services**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Analysis Services encryption at rest posture — model data encryption status, managed identity adoption for data source connections replacing stored credentials, row-level security policy coverage on sensitive models, and audit log configuration — so that DP-4 gaps in tabular model data protection and data source authentication are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Analysis Services encryption at rest controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on managed identity and row-level security configuration manual audit.

**Acceptance Criteria:**
- Analysis Services DP-4 configuration assessed against MCSB baseline and servers with stored data source credentials, missing row-level security on sensitive models, or absent audit logging identified.
- Azure Policy coverage for Analysis Services encryption controls evaluated; built-ins absent for this resource — assessment relies on server property and model security manual audit.
- Gap findings documented with remediation scope and affected Analysis Services server, model row-level security, and data source authentication configurations noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: App Configuration**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure App Configuration encryption at rest posture — default AES-256 encryption status, CMK enablement for stores holding Confidential/Restricted configuration values, managed identity access adoption replacing connection string authentication, and private endpoint network isolation — so that DP-4 gaps in configuration store data protection are identified. Key Azure Policy built-ins applicable: ⚠️ ["App Configuration stores should use private link"](https://www.azadvertizer.net/azpolicyadvertizer.html) (network isolation adjacent — verify DP-4 specific built-ins against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- App Configuration DP-4 configuration assessed against MCSB baseline and stores handling sensitive configuration values without CMK, using connection string authentication, or lacking private endpoint identified.
- Azure Policy compliance evaluated for private link and network isolation controls applicable to App Configuration; DP-4 encryption built-ins absent — manual CMK configuration audit required.
- Gap findings documented with remediation scope and affected App Configuration store, CMK, and network isolation configurations noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: Center for SAP Solutions**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Center for SAP Solutions encryption at rest posture — SAP HANA database encryption configuration, managed disk encryption status on all SAP workload VMs, Azure Backup CMK encryption for SAP backups, and data classification coverage for the SAP landscape — so that DP-4 gaps in SAP data protection across compute and database tiers are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Center for SAP Solutions encryption controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on SAP HANA encryption parameters and VM disk encryption status manual audit.

**Acceptance Criteria:**
- Center for SAP Solutions DP-4 configuration assessed against MCSB baseline and SAP landscapes with unencrypted HANA databases, SAP VMs without managed disk encryption, or backups without CMK identified.
- Azure Policy coverage for SAP Solutions encryption controls evaluated; built-ins absent for this resource — assessment relies on SAP HANA encryption parameters and Azure Backup policy manual audit.
- Gap findings documented with remediation scope and affected SAP HANA database, VM disk, and backup encryption configurations noted.

---

**[SEC-4] Enable Data at Rest Encryption by Default: Data Lake Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Lake Analytics encryption at rest posture — underlying ADLS Gen1 account encryption status with HSM-backed keys, job data encryption in transit to storage, managed identity assignment for compute-to-storage access, and unencrypted job output storage absence — so that DP-4 gaps in analytics job data protection are identified. Key Azure Policy built-ins applicable: ⚠️ ["Require encryption on Data Lake Store accounts"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (applies to underlying ADLS Gen1 account — verify exact scope against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Data Lake Analytics DP-4 configuration assessed against MCSB baseline and analytics accounts with unencrypted underlying ADLS Gen1 stores, missing managed identity for compute-to-storage access, or unencrypted job output destinations identified.
- Azure Policy compliance evaluated for: ⚠️ "Require encryption on Data Lake Store accounts" for underlying ADLS Gen1; scope verification against current MCSB v2 preview required.
- Gap findings documented with remediation scope and affected Data Lake Analytics account, ADLS Gen1 encryption, and job output storage configurations noted.

---

### 5 Use Customer-Managed Key When Required [5 combined]

**[SEC-5] Use Customer-Managed Key When Required: Cosmos DB**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Cosmos DB customer-managed key configuration — CMK enablement status at account level, managed identity integration for Key Vault CMK access, private endpoint and public network access restrictions, and master key usage by applications versus RBAC-based data plane access — so that DP-5 gaps where Cosmos DB accounts store sensitive data without CMK or rely on master keys for application access are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Cosmos DB DP-5 configuration assessed against MCSB baseline and accounts storing sensitive data without CMK enablement or with application access relying on master keys identified.
- Azure Policy compliance evaluated for CMK controls applicable to Cosmos DB; ⚠️ "Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest" flagged for display name verification.
- Gap findings documented with remediation scope and affected Cosmos DB account, CMK configuration, and data plane access method instances noted.

---

**[SEC-5] Use Customer-Managed Key When Required: Synapse Analytics**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Synapse Analytics customer-managed key configuration — workspace CMK enablement via managed identity and Key Vault, dedicated SQL pool TDE CMK status, encryption key rotation policy definition and cadence, and double encryption enablement for workspaces handling Confidential data — so that DP-5 gaps in analytics platform data protection compliance are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Synapse workspaces should use customer-managed keys to encrypt data at rest"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Synapse Analytics DP-5 configuration assessed against MCSB baseline and workspaces without CMK enablement, dedicated SQL pools without TDE CMK, or missing key rotation policy documentation identified.
- Azure Policy compliance evaluated for CMK controls applicable to Synapse workspaces; ⚠️ display name to be verified against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected Synapse workspace, dedicated pool, CMK, and key rotation configurations noted.

---

**[SEC-5] Use Customer-Managed Key When Required: Data Manager for Energy**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Manager for Energy customer-managed key configuration — CMK enablement for data-at-rest encryption, Key Vault integration for customer-owned key management, OSDU data platform encryption compliance status, and key rotation cadence documentation — so that DP-5 gaps in energy sector data protection and key custody requirements are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Data Manager for Energy CMK controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on OSDU platform encryption configuration and Key Vault integration manual audit.

**Acceptance Criteria:**
- Data Manager for Energy DP-5 configuration assessed against MCSB baseline and instances without CMK enablement or missing OSDU encryption compliance documentation identified.
- Azure Policy coverage for Data Manager for Energy CMK controls evaluated; built-ins absent for this resource — assessment relies on OSDU encryption configuration and Key Vault integration manual audit.
- Gap findings documented with remediation scope and affected Data Manager for Energy instance, CMK configuration, and key rotation cadence noted.

---

**[SEC-5] Use Customer-Managed Key When Required: Managed Instance for Apache Cassandra**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Managed Instance for Apache Cassandra customer-managed key configuration — CMK enablement for data-at-rest encryption via Key Vault integration, managed identity assignment, private endpoint network isolation, and managed disk encryption status on Cassandra cluster nodes — so that DP-5 gaps in Cassandra data protection configuration are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Managed Instance for Apache Cassandra should use customer-managed keys to encrypt data at rest"](https://www.azadvertizer.net/azpolicyadvertizer.html) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Managed Instance for Apache Cassandra DP-5 configuration assessed against MCSB baseline and instances without CMK, missing managed identity for Key Vault access, or lacking private endpoint identified.
- Azure Policy compliance evaluated for CMK controls applicable to Managed Instance for Apache Cassandra; ⚠️ display name to be verified against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected Cassandra instance, CMK configuration, and cluster node disk encryption instances noted.

---

**[SEC-5] Use Customer-Managed Key When Required: NetApp Files**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure NetApp Files encryption posture — NetApp Volume Encryption (NVE) status on all volumes, CMK via Azure Key Vault integration where supported by capacity pool type, SMB Kerberos authentication enforcement for NFS/SMB protocol security, and capacity pool encryption coverage — so that DP-5 gaps in NetApp Files data-at-rest protection compliance are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for NetApp Files CMK or volume encryption controls in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on capacity pool and volume encryption configuration manual audit.

**Acceptance Criteria:**
- NetApp Files DP-5 configuration assessed against MCSB baseline and volumes without NVE, capacity pools without CMK where supported, or SMB shares without Kerberos authentication identified.
- Azure Policy coverage for NetApp Files CMK controls evaluated; built-ins absent for this resource — assessment relies on capacity pool encryption type and volume configuration manual audit.
- Gap findings documented with remediation scope and affected NetApp Files capacity pool, volume encryption, and SMB authentication configurations noted.

---

### 6 Use a Secure Key Management Process [3 combined]

**[SEC-6] Use a Secure Key Management Process: Key Vault**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Key Vault key management security posture — RBAC authorization model adoption over legacy access policies, soft delete and purge protection enablement, private endpoint network isolation and firewall deny-public configuration, key rotation policy (RSA-2048+ with 1-year rotation cadence), and audit log completeness for all Key Vault operations — so that DP-6 gaps in cryptographic key lifecycle governance are identified. Key Azure Policy built-ins applicable: ["Key vaults should have soft delete enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key vaults should have purge protection enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault keys should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).

**Acceptance Criteria:**
- Key Vault DP-6 configuration assessed against MCSB baseline and vaults with legacy access policies, missing soft delete or purge protection, public network access enabled, or keys without expiration date set identified.
- Azure Policy compliance evaluated for: ["Key vaults should have soft delete enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key vaults should have purge protection enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault keys should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).
- Gap findings documented with remediation scope and affected Key Vault instance, access policy model, network configuration, and key rotation policy instances noted.

---

**[SEC-6] Use a Secure Key Management Process: Key Vault Managed HSM**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Key Vault Managed HSM security posture — FIPS 140-2 Level 3 validation status, built-in RBAC authorization model adoption without legacy access policies, purge protection enablement, private endpoint network isolation, and HSM key backup and restore policy documentation with tested recovery evidence — so that DP-6 gaps in hardware-backed cryptographic key management governance are identified. Key Azure Policy built-ins applicable: ["Azure Key Vault Managed HSM should have purge protection enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).

**Acceptance Criteria:**
- Key Vault Managed HSM DP-6 configuration assessed against MCSB baseline and HSM pools without purge protection, missing private endpoint, or without tested key backup and restore procedures identified.
- Azure Policy compliance evaluated for: ["Azure Key Vault Managed HSM should have purge protection enabled"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).
- Gap findings documented with remediation scope and affected Managed HSM pool, purge protection, network isolation, and key backup configurations noted.

---

**[SEC-6] Use a Secure Key Management Process: Dedicated HSM**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Dedicated HSM security posture — FIPS 140-2 Level 3 device validation status, VNet integration and public access restriction, physical access control documentation, HSM zeroization policy completeness, and BYOL key management audit evidence — so that DP-6 gaps in customer-managed dedicated hardware security module governance are identified. Key Azure Policy built-ins applicable: ⚠️ [No confirmed Azure Policy built-ins for Azure Dedicated HSM in MCSB v2 preview](https://www.azadvertizer.net/azpolicyadvertizer.html) — assessment relies on VNet integration configuration and HSM device compliance documentation manual audit.

**Acceptance Criteria:**
- Dedicated HSM DP-6 configuration assessed against MCSB baseline and devices without VNet integration, missing physical access control documentation, or absent HSM zeroization policy identified.
- Azure Policy coverage for Dedicated HSM controls evaluated; built-ins absent for this resource — assessment relies on VNet network configuration and FIPS 140-2 Level 3 device compliance manual audit.
- Gap findings documented with remediation scope and affected Dedicated HSM device, VNet integration, and key management policy configurations noted.

---

### 7 Use a Secure Certificate Management Process [pure v2]

**[SEC-7] Use a Secure Certificate Management Process**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess TLS certificate lifecycle management posture across the environment — Key Vault coverage for certificate storage (App Service, API Management, Application Gateway bindings from Key Vault), certificate expiry monitoring alert configuration at 30-day and 7-day thresholds, auto-renewal integration status for ACM/DigiCert-managed certificates, self-signed certificate absence in production, and certificate inventory completeness — so that DP-7 gaps in certificate lifecycle governance and expiry risk across the Azure estate are identified. Key Azure Policy built-ins applicable: ["Key Vault certificates should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault certificates should not expire within the specified number of days"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).

**Acceptance Criteria:**
- Certificate management DP-7 configuration assessed against MCSB baseline and production services with self-signed certificates, missing Key Vault certificate bindings, or absent expiry monitoring alerts identified.
- Azure Policy compliance evaluated for: ["Key Vault certificates should have an expiration date set"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference), ["Key Vault certificates should not expire within the specified number of days"](https://learn.microsoft.com/en-us/azure/key-vault/general/policy-reference).
- Gap findings documented with remediation scope and affected certificate bindings, Key Vault certificate objects, and auto-renewal configurations across App Service, API Management, and Application Gateway noted.

---

### 8 Ensure Security of Key and Certificate Repository [1 combined]

**[SEC-8] Ensure Security of Key and Certificate Repository: Data Box**
Parent: [SEC-DP] Data Protection — MCSB v2
Tags: Security
Description: As a cloud engineer, I want to assess Azure Data Box physical and cryptographic security posture — physical chain of custody documentation completeness, BitLocker disk-level encryption during transit, NIST SP 800-88 data wipe compliance on device return to Microsoft, BitLocker key storage in Key Vault, and shipment tracking plus tamper-evidence review process — so that DP-8 gaps in key and certificate repository physical security and data sanitization are identified. Key Azure Policy built-ins applicable: ⚠️ ["Azure Data Box jobs should enable double encryption for data at rest on the device"](https://learn.microsoft.com/en-us/azure/defender-for-cloud/policy-reference) (training data — verify exact display name against current MCSB v2 preview policy list).

**Acceptance Criteria:**
- Data Box DP-8 configuration assessed against MCSB baseline and jobs without double encryption enabled, missing BitLocker key storage in Key Vault, or absent chain of custody documentation identified.
- Azure Policy compliance evaluated for double encryption controls applicable to Data Box jobs; ⚠️ display name to be verified against current MCSB v2 preview list.
- Gap findings documented with remediation scope and affected Data Box job, BitLocker configuration, and physical security documentation instances noted.

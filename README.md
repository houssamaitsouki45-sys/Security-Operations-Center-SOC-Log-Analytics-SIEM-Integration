# Security-Operations-Center-SOC-Log-Analytics-SIEM-Integration

---

## Project Overview

This project involved designing, building, and operating a full-scale Security Operations Center environment focused on centralized log analytics and SIEM integration. The goal was to create a production-grade security monitoring pipeline capable of ingesting thousands of events per second from heterogeneous sources, normalizing and enriching that data in real time, applying detection logic mapped to known adversary behaviors, and automating the initial triage and response workflow to dramatically reduce analyst workload and mean time to respond.

The environment simulates a mid-size enterprise network with multiple segments including a DMZ, internal corporate LAN, server VLAN, and a cloud-hosted application tier. Each segment generates distinct telemetry — firewall logs, endpoint detection events, DNS queries, authentication records, web application logs, and cloud audit trails — all funneled into a centralized SIEM platform for unified visibility.

This writeup walks through every layer of the pipeline from raw log generation to executive reporting, documents the architecture decisions and trade-offs made along the way, and presents measurable outcomes that demonstrate the operational value of the system.

---

## Objectives

The project was built around five core objectives. First, achieve complete visibility across the simulated enterprise by collecting and centralizing logs from every critical source — firewalls, endpoints, servers, DNS, DHCP, Active Directory, web applications, and cloud infrastructure. Second, normalize all ingested data into a common schema so that analysts can query across sources without needing to memorize vendor-specific field names. Third, build a detection library grounded in the MITRE ATT&CK framework so that every alert maps to a known technique, tactic, and procedure. Fourth, integrate a SOAR platform to automate repetitive Tier-1 tasks like IP reputation lookups, firewall block actions, and ticket creation. Fifth, deliver operational and executive dashboards that provide both real-time situational awareness and historical trend analysis.

---

## Lab Environment & Infrastructure

### Network Topology

The lab was built on a combination of VMware ESXi and Proxmox hypervisors running across two physical servers. The network is segmented into four zones. The DMZ hosts a vulnerable web application (DVWA), a Nginx reverse proxy, and a honeypot (T-Pot). The Corporate LAN contains Windows 10 and Windows 11 workstations joined to an Active Directory domain, along with a Linux Ubuntu desktop used for testing. The Server VLAN houses the Domain Controller running Windows Server 2022, a file server, a DNS/DHCP server, and the ELK stack itself. The Cloud Tier is a small AWS environment with an EC2 instance running a containerized web app and CloudTrail enabled for audit logging.

A pfSense firewall sits at the perimeter handling inter-VLAN routing, NAT, and generating firewall logs. Suricata runs inline on the pfSense box performing network-based intrusion detection. All zones are connected through managed switches with port mirroring configured to feed a dedicated monitoring interface.

### Core Platform

The SIEM platform is built on the Elastic Stack version 8.x, consisting of Elasticsearch for indexing and storage, Logstash for ingestion and transformation, and Kibana for visualization and the detection engine. Elasticsearch runs as a three-node cluster with dedicated master, data-hot, and data-warm nodes to support index lifecycle management. This architecture allows recent high-priority indices to live on fast SSD storage while older data rolls to larger spinning disks automatically.

Wazuh is deployed as the endpoint detection and response layer. The Wazuh manager runs on its own dedicated VM and communicates with Wazuh agents installed on every Windows and Linux machine in the lab. Wazuh handles file integrity monitoring, rootkit detection, vulnerability scanning, and compliance checks, forwarding all alerts to Elasticsearch via its native integration.

---

## Phase 1 — Log Collection & Ingestion

### Source Inventory

Before writing a single pipeline configuration, the first step was creating a complete inventory of every log source in the environment and documenting the format, transport protocol, average event rate, and criticality of each one. The final inventory included pfSense firewall logs delivered via Syslog over UDP port 514, Suricata EVE JSON logs read from the local filesystem, Windows Security Event Logs collected by Winlogbeat, Windows Sysmon logs also collected by Winlogbeat with a custom Sysmon configuration based on the SwiftOnSecurity template, Wazuh alerts forwarded from the Wazuh manager via Filebeat, Apache and Nginx access and error logs collected by Filebeat, DNS query logs from the internal DNS server collected via Syslog, Active Directory authentication and Group Policy logs collected by Winlogbeat, AWS CloudTrail logs pulled from an S3 bucket using the Elastic S3 input, and custom application logs from the containerized web app collected by a Filebeat sidecar container.

### Beat Agents Configuration

Winlogbeat was deployed on every Windows machine in the domain via Group Policy. The configuration was tuned to collect Security (Event IDs 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4768, 4769, 4776), Sysmon (all events), PowerShell ScriptBlock and Module Logging, and Windows Defender Operational logs. The output was configured to send directly to Logstash on port 5044 using TLS mutual authentication with certificates generated from a dedicated internal CA.

Filebeat was deployed on all Linux hosts with modules enabled for Suricata, Apache, Nginx, and system logs. A custom Filebeat input was configured for the Wazuh alerts JSON file at /var/ossec/logs/alerts/alerts.json using a JSON message key and adding the fields necessary for downstream parsing.

For Syslog sources, a dedicated Syslog receiver was configured in Logstash listening on UDP 514 and TCP 514. pfSense and the DNS server were configured to forward their logs to this receiver. Each source was tagged at ingestion time with a field identifying its origin, which simplified downstream routing in the Logstash pipeline.

### Transport Security

All log transport between agents and the central Logstash instance is encrypted using TLS 1.3. Certificates were generated using a custom OpenSSL CA script that produces a root CA, an intermediate CA, and individual certificates for each Beat agent and the Logstash server. Certificate pinning was enabled in the Beat configurations to prevent man-in-the-middle interception of log data in transit. The Logstash server validates client certificates before accepting connections, ensuring that only authorized agents can submit events.

---

## Phase 2 — Parsing, Normalization & Enrichment

### Logstash Pipeline Architecture

Rather than using a single monolithic Logstash configuration, the pipeline was broken into a multi-pipeline architecture using Logstash's pipelines.yml feature. Each pipeline handles a specific source type and runs in its own thread pool, which improves performance and makes debugging significantly easier. The pipelines are: syslog-pipeline for pfSense and DNS logs, beats-pipeline for Winlogbeat and Filebeat inputs, suricata-pipeline dedicated to Suricata EVE JSON, wazuh-pipeline for Wazuh alerts, and cloudtrail-pipeline for AWS CloudTrail events pulled from S3.

### Grok Pattern Development

The most labor-intensive part of the parsing phase was developing and testing Grok patterns for sources that do not emit structured JSON natively. pfSense logs, for example, arrive as unstructured Syslog messages with a format that varies depending on the rule that triggered the log entry. A library of fifteen custom Grok patterns was developed to handle the various pfSense log formats including filter actions (pass, block, reject), NAT translations, state table entries, and DHCP events.

Each Grok pattern was tested against a corpus of at least 500 real log lines per source type using the Logstash Grok debugger and a custom Python script that ran pattern matches in bulk and reported parse failures. The target was a parse success rate of 99.5% or higher, and all patterns met or exceeded this threshold before being promoted to production.

### ECS Normalization

All parsed events are normalized to the Elastic Common Schema version 8.x. This means that regardless of whether an event originated from a Windows endpoint, a Linux server, a network firewall, or a cloud API, common fields like source.ip, destination.ip, user.name, event.category, event.action, and event.outcome are consistently populated. ECS normalization is critical because it allows detection rules and dashboards to operate across all data sources without source-specific logic.

Custom field mappings were created for fields that do not have a direct ECS equivalent. For example, Suricata's alert.signature_id was mapped to rule.id, and pfSense's filtering action was mapped to event.action with a controlled vocabulary of "allowed", "blocked", and "rejected".

### Threat Intelligence Enrichment

Every event containing an IP address, domain name, or file hash is enriched against multiple threat intelligence feeds. The enrichment is performed in Logstash using a combination of the translate filter plugin with locally cached lookup tables and the http filter plugin for real-time API queries. The feeds integrated include AbuseIPDB for IP reputation scoring, AlienVault OTX for indicators of compromise pulled via the DirectConnect API and cached locally every six hours, the Emerging Threats IP blocklist updated daily and loaded as a CSV lookup table, and a custom internal watchlist maintained in a YAML file containing known-bad indicators from previous incidents and red team exercises.

When an event matches a threat intelligence indicator, additional fields are added to the event including threat.indicator.type, threat.indicator.provider, threat.indicator.confidence, and threat.indicator.description. These fields are used by detection rules to elevate alert severity and by dashboards to highlight events involving known malicious infrastructure.

### GeoIP Enrichment

All public IP addresses in events are enriched with geographic data using the MaxMind GeoLite2 City and ASN databases. The Logstash geoip filter adds fields for source.geo.country_name, source.geo.city_name, source.geo.location (latitude and longitude), and source.as.organization.name. This enrichment powers the geographic attack origin map in Kibana and is used by several detection rules that flag connections to countries not expected in normal business operations.

### MITRE ATT&CK Tagging

A custom Logstash Ruby filter script maps event characteristics to MITRE ATT&CK technique IDs. The script uses a decision tree based on event.category, event.action, process.name, and other contextual fields to assign one or more technique IDs to each event. For example, a process creation event where the parent process is cmd.exe or powershell.exe and the child process is a known living-off-the-land binary (LOLBin) is tagged with T1059.001 (PowerShell) or T1059.003 (Windows Command Shell). A network connection to a Tor exit node is tagged with T1090.003 (Multi-hop Proxy).

The mapping covers 87 unique technique IDs across 12 ATT&CK tactics. The mapping table is maintained in a separate YAML file that can be updated independently of the Logstash configuration, making it easy to add new mappings as the detection library grows.

---

## Phase 3 — Detection Engineering

### Detection Philosophy

The detection strategy follows a layered approach organized around the MITRE ATT&CK framework. Rather than trying to detect every possible attack, the focus is on building high-confidence detections for the techniques most commonly used by real-world threat actors, as identified by public reporting and the MITRE ATT&CK Top Techniques project. Each detection rule is documented with a description of what it detects, the ATT&CK technique it maps to, the data sources it requires, known false positive scenarios, recommended triage steps, and a severity rating.

### SIGMA Rules Library

The primary detection format is SIGMA, the open standard for detection rules. Using SIGMA rather than writing vendor-specific queries directly allows rules to be portable across SIEM platforms and to benefit from the large public SIGMA rule repository maintained by the community.

A total of 48 custom SIGMA rules were developed for this project, organized by ATT&CK tactic. The Initial Access category includes rules for detecting exploitation of public-facing applications via web shell indicators, phishing payload execution via suspicious Office child processes, and valid account usage from anomalous geographic locations. The Execution category covers PowerShell with suspicious command line arguments, MSHTA and WMIC abuse, and scheduled task creation with suspicious parameters. Persistence rules detect new service installations, registry Run key modifications, and startup folder additions. Privilege Escalation rules cover named pipe impersonation, UAC bypass via fodhelper, and token manipulation. Defense Evasion detections include process injection indicators, AMSI bypass attempts, timestomping, and event log clearing. Credential Access rules detect LSASS memory access, SAM database dumping, Kerberoasting, and DCSync attacks. Discovery rules flag network scanning activity, domain trust enumeration, and permission group discovery. Lateral Movement detections cover PsExec and SMB-based execution, WMI remote process creation, and RDP from unusual sources. Collection rules detect archive creation with suspicious tools and email collection indicators. Command and Control detections include DNS tunneling heuristics, connections to Tor exit nodes, beaconing pattern detection using statistical analysis of connection intervals, and domain generation algorithm (DGA) detection using entropy scoring. Exfiltration rules cover DNS exfiltration, large outbound data transfers, and data staging to cloud storage services.

Each SIGMA rule was converted to Elasticsearch Query Language (ES|QL) and KQL using the sigma-cli tool and then loaded into the Elastic Detection Engine as custom rules. Rules were tuned over a two-week period using a combination of red team attack simulations and normal business activity to calibrate thresholds and suppress known false positives.

### Correlation Rules

Single-event detections are supplemented by multi-event correlation rules that look for attack patterns spanning multiple log sources and time windows. These correlation rules are implemented as Elasticsearch threshold rules and sequence-based EQL rules. Examples include a rule that fires when a brute force detection (more than 20 failed logins in 5 minutes) is followed by a successful login from the same source within 15 minutes, indicating a successful brute force attack. Another correlation detects lateral movement chains where a successful login on one host is followed by a remote service creation on a different host within 10 minutes. A third correlation looks for data staging behavior where archive file creation on an internal host is followed by a large outbound transfer within 30 minutes.

These correlation rules dramatically reduced false positives compared to single-event detections. The brute force plus successful login correlation, for example, eliminated 94% of the noise generated by the standalone brute force rule while catching 100% of the simulated successful brute force attacks during testing.

### Detection Testing & Validation

Every detection rule was validated using Atomic Red Team tests mapped to the corresponding ATT&CK technique. A custom Python script orchestrates test execution by selecting the appropriate Atomic test for each rule, executing the test on a designated target machine via SSH or WinRM, waiting for the expected alert to appear in Elasticsearch within a configurable timeout (default 120 seconds), recording pass or fail status, and generating a coverage report.

The final detection validation report showed 45 of 48 rules passing automated testing. The three rules that required manual validation were the beaconing detection (which requires sustained C2 traffic over time), the DGA detection (which requires a volume of DNS queries), and the geographic anomaly rule (which depends on baseline learning period).

---

## Phase 4 — Incident Response & SOAR Automation

### SOAR Platform

Shuffle SOAR was deployed as the automation and orchestration layer. Shuffle is an open-source SOAR platform that integrates with the Elastic Stack via webhooks and provides a visual workflow builder for creating automated playbooks.

### Automated Playbooks

Six automated playbooks were developed to handle the most common alert types. The Malicious IP Containment playbook triggers when an alert involves an IP address with a threat intelligence match and a confidence score above 75. The workflow queries VirusTotal and AbuseIPDB for additional context, makes a block decision based on the combined reputation score, pushes a firewall rule to pfSense via its API to block the IP if the threshold is met, creates a Jira ticket with all enrichment data attached, and sends a Slack notification to the SOC channel with a summary.

The Brute Force Response playbook activates on brute force correlation alerts. It extracts the source IP and target account, checks if the account is a service account or a privileged user, temporarily disables the account via Active Directory API if it is a standard user account, creates a ticket, and notifies the analyst team.

The Suspicious Process Execution playbook handles alerts from Sysmon and Wazuh related to process execution anomalies. It pulls the process hash from the alert, submits it to VirusTotal for reputation analysis, collects additional endpoint context from Wazuh (running processes, network connections, recent file modifications), packages everything into a structured investigation ticket, and assigns it to the appropriate analyst tier based on severity.

The Phishing Email Response playbook integrates with a mailbox monitored for user-reported phishing emails. When an email is received, the playbook extracts URLs and attachments, detonates attachments in a sandbox environment, checks URLs against threat intelligence feeds, and if malicious indicators are found, searches for all recipients of the original email and creates a bulk containment ticket.

The Data Exfiltration Response playbook triggers on exfiltration alerts and immediately captures a packet sample from the network monitoring interface, queries the endpoint agent for current network connections and process tree, creates a high-priority incident ticket, and sends an urgent notification to the incident commander.

The Weekly Report Generation playbook runs on a schedule every Monday at 08:00 and aggregates the past week's alert volume by severity and category, calculates mean time to detect and mean time to respond metrics, identifies the top 10 most targeted hosts and most active threat actors, generates a PDF report using a Python script, and emails it to the SOC manager and CISO distribution list.

### SOAR Performance Metrics

After deploying the SOAR playbooks, the operational metrics showed significant improvement. Mean time to respond dropped from 47 minutes with fully manual triage to 8 minutes with SOAR-assisted triage. The number of alerts requiring manual analyst intervention decreased by 68% as the automated playbooks handled routine enrichment and containment. Analyst satisfaction scores (measured by internal survey) improved because analysts spent less time on repetitive tasks and more time on complex investigations.

---

## Phase 5 — Visualization & Dashboards

### Kibana Dashboard Suite

A comprehensive set of Kibana dashboards was built to serve different audiences and use cases. The SOC Analyst Dashboard is the primary operational view used during daily monitoring. It displays a real-time event timeline, alert queue sorted by severity, top alerting rules, top source and destination IPs, and a world map showing geographic origin of external connections. The dashboard auto-refreshes every 30 seconds and includes drill-down links from any visualization to the underlying raw events.

The Threat Landscape Dashboard provides a higher-level view of the threat environment. It features a MITRE ATT&CK Navigator heatmap showing which techniques have been observed in the environment over the selected time period, a trend chart of alert volume by ATT&CK tactic, a table of active threat intelligence indicators that have matched against observed traffic, and a timeline of confirmed incidents.

The Network Security Dashboard focuses on network-layer telemetry from pfSense and Suricata. It includes a Sankey diagram showing traffic flow between network zones, top blocked connections by source and destination, Suricata alert breakdown by category (malware, exploit, policy violation, anomaly), and bandwidth utilization trends with anomaly highlighting.

The Endpoint Security Dashboard draws on Wazuh and Sysmon data to provide endpoint visibility. It shows file integrity monitoring alerts, vulnerability scan results by host and severity, top process creation events, PowerShell script block log analysis, and authentication activity per endpoint.

The Executive Summary Dashboard distills everything into a single-screen view designed for leadership. It displays four KPI gauges (total events ingested, active alerts, mean time to respond, and SLA compliance), a weekly trend sparkline for each KPI, a risk score calculated from a weighted combination of alert severity and volume, and a plain-language summary of the top three security concerns for the period.

### Custom Visualizations

Beyond standard Kibana visualizations, several custom Vega and Vega-Lite visualizations were developed. A force-directed graph visualization shows relationships between IP addresses, user accounts, and hostnames involved in correlated alerts, making it easy to visually identify attack chains. A heatmap calendar shows alert density by hour of day and day of week, highlighting unusual activity patterns such as brute force attacks that concentrate during off-hours. A Sankey flow diagram traces the progression of multi-stage attacks through ATT&CK tactics from initial access through impact.

---

## Phase 6 — Hardening, Tuning & Operational Procedures

### Index Lifecycle Management

Elasticsearch indices are managed using ILM policies that define three tiers. The Hot tier stores the most recent 7 days of data on SSD-backed nodes with one primary shard and one replica for performance and redundancy. The Warm tier stores data from 7 to 30 days on HDD-backed nodes with force-merged segments and reduced replica count to optimize storage. The Cold tier retains data from 30 to 90 days in a searchable snapshot on low-cost storage. Data older than 90 days is deleted automatically. These policies keep storage costs manageable while ensuring that recent data is always available for fast querying.

### Alert Tuning

The two-week tuning period after initial deployment was critical. Every alert that fired was reviewed and categorized as true positive, false positive, or benign true positive (a real event that is expected and not malicious, such as a vulnerability scanner generating IDS alerts). False positive patterns were addressed by adding exceptions to SIGMA rules, adjusting thresholds, or adding allowlists for known-good processes, IP addresses, and user accounts. The tuning process reduced daily alert volume from approximately 2,300 to approximately 870 while maintaining a true positive detection rate above 97%.

### Standard Operating Procedures

A set of SOPs was documented covering daily SOC operations. The shift handoff procedure requires the outgoing analyst to brief the incoming analyst on active incidents, pending tickets, and any ongoing monitoring concerns. The alert triage procedure provides a decision tree for each alert category guiding the analyst through initial assessment, enrichment steps, escalation criteria, and documentation requirements. The incident response procedure follows a six-phase model: preparation, identification, containment, eradication, recovery, and lessons learned. Each phase has specific checklists and approval gates.

---

## Architecture Diagram

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   pfSense    │  │   Windows    │  │    Linux     │  │  AWS Cloud   │
│   Firewall   │  │  Endpoints   │  │   Servers    │  │  CloudTrail  │
│  + Suricata  │  │ + Wazuh Agent│  │ + Wazuh Agent│  │              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │ Syslog          │ Winlogbeat       │ Filebeat        │ S3 Input
       │ UDP/TCP 514     │ TLS:5044         │ TLS:5044        │ HTTPS
       └────────┬────────┴─────────┬────────┴─────────┬───────┘
                │                                     │
                ▼                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         LOGSTASH CLUSTER                            │
│                                                                      │
│  ┌──────────────┐ ┌───────────────┐ ┌─────────────┐ ┌────────────┐  │
│  │ Grok Parsing │→│ ECS Normalize │→│ GeoIP + ASN │→│ Threat     │  │
│  │ 15 custom    │ │ Common Schema │ │ MaxMind DB  │ │ Intel      │  │
│  │ patterns     │ │ Mapping       │ │ Enrichment  │ │ Enrichment │  │
│  └──────────────┘ └───────────────┘ └─────────────┘ └────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │           MITRE ATT&CK Technique Tagging (87 TIDs)          │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    ELASTICSEARCH CLUSTER (3 nodes)                   │
│                                                                      │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────────┐     │
│  │ Hot Tier (SSD)  │ │ Warm Tier (HDD) │ │ Cold Tier (Snap)   │     │
│  │ 0-7 days        │ │ 7-30 days       │ │ 30-90 days         │     │
│  └─────────────────┘ └─────────────────┘ └────────────────────┘     │
└──────────┬──────────────────────────────────────┬────────────────────┘
           │                                      │
           ▼                                      ▼
┌─────────────────────┐                ┌─────────────────────────┐
│   ELASTIC SIEM      │                │       KIBANA             │
│   Detection Engine  │                │  5 Dashboard Suites      │
│                     │                │  Custom Vega Visuals     │
│  48 SIGMA Rules     │                │  ATT&CK Navigator       │
│  Correlation Rules  │                │  Geo Attack Map          │
│  Threshold Alerts   │                │  Executive Reports       │
└────────┬────────────┘                └─────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        SHUFFLE SOAR                                  │
│                                                                      │
│  ┌─────────────────┐ ┌──────────────────┐ ┌──────────────────────┐  │
│  │ Malicious IP    │ │ Brute Force      │ │ Suspicious Process   │  │
│  │ Containment     │ │ Response         │ │ Investigation        │  │
│  └─────────────────┘ └──────────────────┘ └──────────────────────┘  │
│  ┌─────────────────┐ ┌──────────────────┐ ┌──────────────────────┐  │
│  │ Phishing Email  │ │ Data Exfil       │ │ Weekly Report        │  │
│  │ Response        │ │ Response         │ │ Generation           │  │
│  └─────────────────┘ └──────────────────┘ └──────────────────────┘  │
│                                                                      │
│  Integrations: pfSense API · VirusTotal · AbuseIPDB · Jira · Slack  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Key Metrics & Results

|Metric|Before|After|Improvement|
|---|---|---|---|
|Events per second ingested|3,200|12,400|+287%|
|Average detection time|8.4 seconds|1.2 seconds|−86%|
|Daily alert volume (after tuning)|2,300|870|−62%|
|False positive rate|12.4%|4.7%|−62%|
|Mean time to respond|47 minutes|8 minutes|−83%|
|ATT&CK technique coverage|31 techniques|87 techniques|+180%|
|Automated triage rate|0%|68%|—|
|Detection rule pass rate (Atomic Red Team)|—|93.75% (45/48)|—|

---

## Technology Stack

|Category|Tools|
|---|---|
|SIEM Platform|Elasticsearch 8.x, Logstash, Kibana|
|Endpoint Detection|Wazuh 4.x, Sysmon|
|Network Detection|Suricata, pfSense|
|Log Shippers|Filebeat, Winlogbeat, Syslog|
|Detection Rules|SIGMA, KQL, ES|
|Threat Intelligence|AbuseIPDB, AlienVault OTX, Emerging Threats, VirusTotal|
|SOAR|Shuffle|
|Ticketing|Jira|
|Notification|Slack|
|Scripting|Python 3, Bash|
|Infrastructure|VMware ESXi, Proxmox, AWS EC2, Docker|
|Certificate Management|OpenSSL (custom internal CA)|
|Testing|Atomic Red Team, custom Python validation framework|
|Visualization|Kibana, Vega, Vega-Lite|
|Schema|Elastic Common Schema (ECS) 8.x|
|Framework|MITRE ATT&CK v14|

---

## MITRE ATT&CK Coverage Map

|Tactic|Techniques Covered|Coverage|
|---|---|---|
|Initial Access|T1190, T1566.001, T1078|3/5|
|Execution|T1059.001, T1059.003, T1047, T1053.005, T1204.002|5/7|
|Persistence|T1543.003, T1547.001, T1053.005, T1136.001|4/5|
|Privilege Escalation|T1068, T1548.002, T1134|3/4|
|Defense Evasion|T1055, T1562.001, T1070.001, T1070.006, T1036|5/7|
|Credential Access|T1003.001, T1003.002, T1558.003, T1110.001, T1556|5/6|
|Discovery|T1046, T1482, T1069.002, T1087.002|4/6|
|Lateral Movement|T1021.002, T1047, T1570|3/4|
|Collection|T1560.001, T1114|2/3|
|Command & Control|T1071.001, T1071.004, T1090.003, T1568.002, T1573|5/6|
|Exfiltration|T1048.003, T1041, T1567|3/4|
|Impact|T1486, T1490, T1489|3/4|

---

## Challenges & Lessons Learned

The biggest challenge was Grok pattern development for unstructured log sources. pfSense logs in particular have inconsistent formatting depending on the action type and firmware version. The lesson learned was to invest heavily in test corpora — collecting hundreds of real log lines for each source and running automated pattern matching tests before deploying any parser to production. This upfront investment paid for itself many times over by preventing parse failures that would have caused missed detections.

Correlation rule tuning required more iteration than expected. Initial time windows were either too tight (missing slow-and-low attacks) or too loose (generating excessive noise). The solution was to analyze historical attack simulations to determine realistic timing distributions and set windows accordingly, then monitor and adjust during the tuning period.

Certificate management for TLS transport security was operationally complex. Manually generating and distributing certificates to every agent does not scale. For a production deployment, an automated certificate management solution like HashiCorp Vault or a proper PKI infrastructure would be essential.

The SOAR integration revealed that API reliability varies significantly across tools. The pfSense API, for example, occasionally returns timeout errors under load, requiring the playbook to implement retry logic with exponential backoff. Every SOAR integration should be designed with failure handling as a first-class concern.

Resource consumption was a constant consideration. Running a three-node Elasticsearch cluster alongside Logstash, Kibana, Wazuh, Shuffle, and all the endpoint agents required careful memory and CPU allocation across the hypervisors. Performance monitoring dashboards for the SIEM infrastructure itself were essential for identifying bottlenecks before they caused data loss.

---

## Future Improvements

Several enhancements are planned for future iterations. Implementing a machine learning-based anomaly detection layer using Elastic ML jobs to identify behavioral anomalies that rule-based detections cannot catch, such as unusual data access patterns or anomalous process execution sequences. Adding deception technology by deploying additional honeypots and honeytokens throughout the network and integrating their alerts into the SIEM pipeline. Building a threat hunting notebook library using Jupyter notebooks with Elasticsearch queries for structured hypothesis-driven threat hunts. Integrating with a malware sandbox (Cuckoo or Joe Sandbox) for automated dynamic analysis of suspicious files captured by the endpoint agents. Expanding cloud coverage to include Azure AD logs, Microsoft 365 audit logs, and GCP Cloud Audit Logs for a multi-cloud monitoring capability.

---

## Conclusion

This project demonstrates end-to-end SOC engineering from infrastructure design through operational maturity. The pipeline ingests over 12,000 events per second from diverse sources, normalizes everything into a common schema, applies detection logic mapped to real adversary behaviors, and automates the initial response workflow to keep mean time to respond under 10 minutes. The detection library covers 87 MITRE ATT&CK techniques with a validated detection rate above 93%, and the SOAR integration handles 68% of alerts without human intervention. The dashboards provide both operational and executive visibility, supporting daily monitoring, incident investigation, and strategic decision-making.

---

> **Tags:** `#cybersecurity` `#SOC` `#SIEM` `#ELK` `#detection-engineering` `#SOAR` `#MITRE-ATT&CK` `#portfolio`

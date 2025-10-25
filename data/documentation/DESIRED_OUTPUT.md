## Agent Operational Document: Automated Security Analysis Report Schema

### 1.0 Overview

This document defines the schema and data logic for the JSON object produced by the automated analysis engine. The purpose of this object is to provide a complete, enriched, and actionable triage package for any given security alert, transforming raw data into security intelligence.

### 2.0 Root Object Structure

The output is a single JSON object with the following top-level keys:

| Key                 | Data Type | Description                                                                         |
| :------------------ | :-------- | :---------------------------------------------------------------------------------- |
| `analysis_metadata` | Object    | Contains metadata about the analysis process itself.                                |
| `alert_id`          | String    | The unique identifier of the original alert that triggered this analysis.           |
| `triage_summary`    | Object    | The final verdict and high-level summary of the investigation.                      |
| `evidence_locker`   | Object    | A collection of all correlated data points used to reach the verdict.               |
| `course_of_action`  | Object    | A prescriptive set of recommended actions for response and remediation.             |

---

### 3.0 Field-by-Field Breakdown

#### 3.1 `analysis_metadata`

**Purpose:** To track the state and context of the analysis job.

| Field                     | Logic & Data Source                                                                             |
| :------------------------ | :---------------------------------------------------------------------------------------------- |
| `analysis_id`             | **[Generate]** Create a unique ID for this analysis instance (e.g., "ANA-" + timestamp + random hex). |
| `alert_id`                | **[Link]** The ID of the source alert. Used as the primary key for this workflow.               |
| `analysis_timestamp`      | **[Generate]** The ISO 8601 timestamp of when this analysis was completed.                       |
| `analysis_engine_version` | **[Static]** The version of the analysis engine code that produced this report.                   |
| `status`                  | **[State]** The current state of the analysis. Possible values: `Pending Analysis`, `Completed`, `Failed`. |

#### 3.2 `alert_id`

**Purpose:** To link this analysis back to the originating event without duplicating data.

| Field      | Logic & Data Source                                                                                                |
| :--------- | :----------------------------------------------------------------------------------------------------------------- |
| `alert_id` | **[Extract]** From the incoming alert data. If no explicit ID exists, generate one from a hash of the alert content. |

#### 3.3 `triage_summary`

**Purpose:** To provide the final, human-readable conclusion of the analysis. This is the most critical output.

| Field                   | Logic & Data Source                                                                                                                                                                                                                              |
| :---------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `final_verdict`         | **[Calculate]** The final classification. Must be one of: `True Positive`, `Benign True Positive`, `False Positive`. This is determined by the weighted evidence in the `evidence_locker`.                                                          |
| `calculated_severity`   | **[Calculate]** Re-evaluate the alert's initial priority using a risk matrix: `(Asset Criticality + User Privilege + Threat Confidence) = Calculated Severity`. An alert on a "Critical" asset is always at least "High".                             |
| `confidence_score`      | **[Calculate]** A weighted score (0-100) based on evidence. **Example Weights:** Threat Intel Match (+50), Malicious EDR Process Chain (+40), Policy Violation (+20), UEBA Anomaly (+15), Benign Context (e.g., user is traveling) (-70). |
| `triage_summary_text`   | **[Generate]** Use a template: "[Verdict] involving user [User] on asset [Hostname] ([Asset Criticality]) performing [Action]. The activity is confirmed by [Key Evidence]."                                                                    |
| `mitre_attack_mapping`  | **[Map]** An array of objects. Map alert signatures and EDR evidence to the MITRE ATT&CK framework using an internal mapping table (e.g., `event_type: ProcessAccess`, `target_process: lsass.exe` -> `T1003.001: OS Credential Dumping: LSASS Memory`). |

#### 3.4 `evidence_locker`

**Purpose:** To provide a transparent and auditable trail of all the data used in the analysis. **Show your work.**

| Field                         | Logic & Data Source                                                                                                                                                                                               |
| :---------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `correlated_cmdb_assets`      | **[Query]** Extract all hostnames and IPs from the alert. Query the **CMDB** for matching `ci_id`, `hostname`, or `ip_address`. Append the full, matching object(s) to this array.                                 |
| `correlated_iam_users`        | **[Query]** Extract all usernames from the alert and correlated logs. Query the **IAM/HR Database** for matching `username`. Append the full, matching object(s) to this array. Check the `on_call_travel_status` flag to help resolve geofence alerts. |
| `policy_violations`           | **[Query]** Extract `source_vlan`, `destination_vlan`, `port`, `protocol`. Query the **Port & Service Policy**. If `status` is `Forbidden`, or if `status` is `Restricted` and zones do not match, append the policy object here. |
| `threat_intelligence_matches` | **[Query]** Extract all external IPs, domains, and file hashes. Query the **Threat Intelligence Database** for matches. If a match is found (and is not purely "Informational"), append the full indicator object here. |
| `correlated_log_evidence`     | **[Query]** A container for log snippets. Query the **EDR, DNS, and Web Proxy** log data stores using the timeframe, IPs, and hostnames from the alert. Append the 1-3 most relevant log entries that prove the activity. |
| `vulnerability_status`        | **[Query]** Query the **Vulnerability Scan Database** for the asset's hostname/IP. If relevant vulnerabilities are found (especially `Open` or `Mitigated` ones), append the finding summary here.            |
| `ueba_anomalies`              | **[Query]** Query the **UEBA Profile Database** for the user/host. Compare the alert's activity (time, location, process, etc.) against the baseline. If there are deviations, describe them here.             |

#### 3.5 `course_of_action`

**Purpose:** To provide a clear, actionable response plan. This bridges the gap between analysis and action.

| Field                             | Logic & Data Source                                                                                                                                                                                                                                                                     |
| :-------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `recommended_playbook_id`         | **[Map]** Based on the `final_verdict` and `mitre_attack_mapping`, select the appropriate playbook ID from a mapping table (e.g., `Verdict: True Positive` + `Tactic: Impact` -> `PB-RANSOM-001`). If verdict is not `True Positive`, this can be `null`. |
| `playbook_name`                   | **[Lookup]** The human-readable name of the recommended playbook.                                                                                                                                                                                                                        |
| `automated_or_one_click_actions`  | **[Generate]** Based on the selected playbook, generate a list of specific, executable actions. The `action` should be a standardized command (e.g., `ISOLATE_HOST`, `BLOCK_IP`, `DISABLE_USER`), and the `target` should be the entity (hostname, IP, username) from the evidence locker. |
| `next_steps_for_analyst`          | **[Copy]** Copy the relevant procedural steps (e.g., for communication, deeper forensics) directly from the recommended **Incident Response Playbook** document. These are tasks that require human intervention.                                      |
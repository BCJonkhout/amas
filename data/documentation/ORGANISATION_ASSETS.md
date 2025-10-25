## Enterprise Security Data & API Endpoint Documentation

### Overview

This document provides a comprehensive overview of the data sources available via the corporate Security Data Fabric. These data endpoints are critical for enriching security alerts, enabling automated analysis, and empowering effective incident response. Each endpoint provides access to a key dataset, representing a specific facet of our IT and security environment.

### 1. `assets/cmdb` (`cmdb.json`)

*   **Endpoint Description:** Provides a comprehensive and authoritative inventory of all configuration items (CIs) across the enterprise network. This is the foundational dataset for identifying and assessing the business context of any asset involved in a security event.
*   **Strategic Importance:** Answers the question, "What is this asset and how important is it?" It is the primary source for determining asset criticality, function, and ownership, which are essential for risk assessment and incident prioritization.
*   **Key Data Fields:**
    *   `ci_id`: Unique identifier for the configuration item.
    *   `hostname`: The asset's hostname.
    *   `ip_address`, `mac_address`: Network identifiers.
    *   `asset_type`: e.g., "Virtual Server", "Laptop", "Firewall".
    *   `os`, `os_version`: Operating system details.
    *   `function`: A human-readable description of the asset's business purpose.
    *   `asset_owner_dept`: The responsible business department.
    *   `business_criticality`: "Critical", "High", "Medium", "Low".
    *   `status`: "Production", "Development", "Decommissioned".
    *   `edr_agent_installed`: Boolean flag indicating EDR visibility.
    *   `patch_status`: "Up-to-date", "Pending-Reboot", "Missing-Critical-Patches".

### 2. `identity/iam` (`iam_hr_database.json`)

*   **Endpoint Description:** Serves as the central repository for all user and service account identities. It maps digital identities to roles, departments, and privilege levels within the organization.
*   **Strategic Importance:** Answers the question, "Who is this user and what are they authorized to do?" This endpoint is crucial for detecting compromised accounts, identifying insider threats, and validating user actions against their expected roles.
*   **Key Data Fields:**
    *   `username`: The unique user login name.
    *   `full_name`: The employee's full name.
    *   `department`, `role_title`: Organizational context.
    *   `account_status`: "Active", "Disabled", "On Leave".
    *   `privileged_access`: An array of high-privilege group memberships (e.g., "Domain Admins").
    *   `on_call_travel_status`: A boolean flag indicating if the user is expected to be working off-hours or from unusual locations.

### 3. `network/vlan_architecture` (`network-architecture_vlan_documentation.json`)

*   **Endpoint Description:** Provides the definitive architectural map of the corporate network, detailing all VLANs, their associated IP subnets, and their intended security posture.
*   **Strategic Importance:** Answers the question, "Where did this traffic come from and where is it going?" This data allows for the validation of network traffic flows against their intended design, making it possible to detect policy violations and lateral movement attempts.
*   **Key Data Fields:**
    *   `vlan_id`: The numeric VLAN identifier.
    *   `vlan_name`: A descriptive name (e.g., "VLAN-ServerFarm-Production").
    *   `ip_range`: The CIDR notation for the subnet.
    *   `description`: The business purpose of the network segment.
    *   `security_policy_summary`: A human-readable summary of the traffic rules governing this VLAN.

### 4. `policy/service_usage` (`approved_port_service_usage_policy.json`)

*   **Endpoint Description:** A granular policy document that defines the authorized use of network services and protocols across different network zones. It acts as the "rulebook" for network communication behavior.
*   **Strategic Importance:** Answers the question, "Is this specific communication allowed?" It provides the ground truth for determining if a given network flow is a policy violation, which is often a strong indicator of malicious or unauthorized activity.
*   **Key Data Fields:**
    *   `policy_id`: A unique identifier for the policy rule.
    *   `port_protocol`: e.g., "TCP/445", "UDP/53".
    *   `service_name`: e.g., "SMB", "DNS".
    *   `status`: "Allowed", "Restricted", "Forbidden".
    *   `authorized_source_zones`, `authorized_destination_zones`: Arrays of `vlan_name`s where traffic is permitted to originate from and travel to.

### 5. `threatintel/indicators` (`threat_intelligence.json`)

*   **Endpoint Description:** Provides a near real-time feed of known malicious indicators of compromise (IoCs), including IP addresses, domains, and file hashes, aggregated from commercial and open-source feeds.
*   **Strategic Importance:** Answers the question, "Is this external entity known to be malicious?" A match against this data provides a high-confidence signal to escalate an alert to a confirmed incident.
*   **Key Data Fields:**
    *   `indicator_value`: The IP, domain, or hash.
    *   `indicator_type`: "ipv4", "domain", "sha256_hash".
    *   `threat_name`, `malware_family`: Context about the associated threat.
    *   `confidence`: "High", "Medium", "Informational".
    *   `last_seen`: The most recent timestamp the indicator was observed in the wild.

### 6. `behavior/ueba_profiles` (`user_entity_behaviour_analytics.json`)

*   **Endpoint Description:** Contains machine-learning-generated behavioral baselines for key users and entities (hosts) on the network. It profiles "normal" activity over time.
*   **Strategic Importance:** Answers the question, "Is this activity normal for this specific user or device?" It is essential for detecting anomalies and sophisticated threats that might not violate a static rule but deviate significantly from established patterns.
*   **Key Data Fields:**
    *   `entity_type`: "User" or "Host".
    *   `entity_name`: The username or hostname.
    *   `profile_maturity`: "Mature", "Learning".
    *   `behavioral_baseline`: An object containing learned patterns like `typical_logon_hours`, `common_source_countries`, `normal_data_egress_volume_mb_per_day`, and `common_processes_executed`.

### 7. `logs/endpoint_telemetry` (`endpoint_security_logs.json`)

*   **Endpoint Description:** A stream of detailed telemetry events from the enterprise Endpoint Detection and Response (EDR) solution, providing granular visibility into process execution, file system activity, and network connections at the host level.
*   **Strategic Importance:** Provides the ground truth for "what happened on the endpoint." It is indispensable for incident response and forensic analysis, allowing analysts to trace the exact chain of execution of an attack.
*   **Key Data Fields:**
    *   `hostname`, `ip_address`: Endpoint identifiers.
    *   `event_type`: "ProcessCreate", "NetworkConnection", "FileWrite", "ProcessAccess", etc.
    *   `process_name`, `process_path`, `file_hash_sha256`: Details of the acting process.
    *   `parent_process_name`, `parent_process_path`: Information for tracing execution flow.
    *   `full_command_line`: The exact command line used to launch a process.

### 8. `logs/web_gateway` (`web_proxy_dns_logs.json`)

*   **Endpoint Description:** A consolidated feed of all outbound web proxy and internal DNS query logs. This provides a complete record of how internal assets are interacting with internet-based resources.
*   **Strategic Importance:** Crucial for identifying connections to malicious sites, detecting DNS-based exfiltration techniques, and auditing user web activity during investigations.
*   **Key Data Fields (DNS):**
    *   `source_ip`, `query_name`, `query_type`, `response_code`.
*   **Key Data Fields (Proxy):**
    *   `source_ip`, `user_id`, `destination_domain`, `full_url`, `url_category`, `action` ("Allowed" or "Blocked").

### 9. `vulns/scans` (`vulnerability_scan_database.json`)

*   **Endpoint Description:** A database of all identified vulnerabilities on corporate assets, compiled from the organization's vulnerability scanning platform.
*   **Strategic Importance:** Answers the question, "Is this asset susceptible to a given attack?" It is a key data point for prioritizing alerts, differentiating between successful and unsuccessful attack attempts, and guiding remediation efforts.
*   **Key Data Fields:**
    *   `hostname`, `ip_address`: The affected asset.
    *   `cve_id`: The Common Vulnerabilities and Exposures identifier.
    *   `vulnerability_name`, `severity`, `cvss_v3_score`: Risk context.
    *   `status`: "Open", "Patched", "Mitigated", "Risk Accepted".

### 10. `response/playbooks` (`incident_response_playbooks.json`)

*   **Endpoint Description:** A repository of standardized, step-by-step procedures for responding to specific types of security incidents. This is a procedural, rather than a data, endpoint.
*   **Strategic Importance:** Provides the "what to do now" for analysts and automation platforms. It ensures that responses are fast, consistent, and follow best practices, reducing human error during a crisis.
*   **Key Data Fields:**
    *   `playbook_id`, `playbook_name`: Identifiers for the procedure.
    *   `incident_type`: The category of incident this playbook addresses (e.g., "Ransomware").
    *   `severity_criteria`: Guidelines for classifying the incident.
    *   `containment_steps`: Specific, actionable commands to stop the threat.
    *   `eradication_steps`: Procedures for removing the threat from the environment.
    *   `recovery_steps`: Steps to restore normal operations.
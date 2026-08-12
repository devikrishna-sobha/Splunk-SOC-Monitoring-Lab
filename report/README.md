# Windows Endpoint Monitoring and Threat Detection Using Splunk and Sysmon

## 1. Project Overview

This project implements a Windows endpoint monitoring and security event detection environment using Splunk Enterprise and Microsoft Sysmon.

The objective was to collect Windows endpoint telemetry, forward Sysmon Operational events to Splunk, analyze security events using SPL queries, and create a basic Security Operations Center (SOC) monitoring dashboard.

The project was performed in a controlled Windows laboratory environment.

---

## 2. Objectives

The main objectives of this project were:

* Install and configure Splunk Enterprise.
* Install and configure Microsoft Sysmon.
* Collect Sysmon Operational logs.
* Integrate Sysmon logs with Splunk.
* Monitor process creation activity.
* Detect PowerShell activity.
* Monitor successful Windows logins.
* Develop SPL-based security detection queries.
* Create a SOC monitoring dashboard.
* Map relevant detections to MITRE ATT&CK.
* Document the implementation and results.

---

## 3. Technologies Used

| Technology           | Purpose                             |
| -------------------- | ----------------------------------- |
| Windows 11           | Endpoint and laboratory environment |
| Splunk Enterprise    | SIEM and log analysis               |
| Microsoft Sysmon     | Endpoint telemetry                  |
| Windows Event Viewer | Event verification                  |
| SPL                  | Security event searching            |
| GitHub               | Project documentation               |
| MITRE ATT&CK         | Threat technique mapping            |

---

## 4. Project Architecture

```text
Windows Endpoint
       |
       v
     Sysmon
       |
       v
Windows Event Logs
       |
       v
Splunk Event Collection
       |
       v
Splunk Enterprise
       |
       v
SPL Detection Queries
       |
       v
SOC Dashboard
       |
       v
Security Investigation
```

---

## 5. Splunk Installation

Splunk Enterprise was installed on the Windows endpoint and configured for local security-event monitoring.

The Splunk Web interface was accessed through the local Splunk instance.

Splunk was tested using searches against the collected Windows and Sysmon events.

---

## 6. Sysmon Installation and Configuration

Microsoft Sysmon was installed to provide detailed endpoint telemetry.

The project focused mainly on:

**Sysmon Event ID 1 – Process Creation**

The Sysmon Operational channel used during the project was:

```text
Microsoft-Windows-Sysmon/Operational
```

Sysmon records detailed information about processes running on the Windows endpoint, including process names, command lines, users, and parent processes.

---

## 7. Sysmon Integration with Splunk

The Windows Sysmon Operational log was configured for collection by Splunk.

The Sysmon sourcetype used for searching was:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

The integration was verified by searching for Sysmon events in Splunk.

Example:

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count
```

The presence of Sysmon events confirmed that the endpoint telemetry was successfully available in Splunk.

---

## 8. Detection Use Cases

### 8.1 Sysmon Event ID 1 – Process Creation

Sysmon Event ID 1 records process creation activity.

Query:

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time Computer User Image CommandLine ParentImage
```

### Purpose

This detection helps a SOC analyst investigate:

* Newly created processes
* Suspicious executables
* Command-line activity
* Parent-child process relationships
* Potential malicious process execution

---

### 8.2 PowerShell Activity

PowerShell activity was monitored through Sysmon process-creation events.

Query:

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell*" OR CommandLine="*PowerShell*"
| stats count
```

### Purpose

PowerShell is a legitimate administration tool but can also be abused by attackers.

This detection helps identify PowerShell execution on the endpoint.

---

### 8.3 Successful Login – Event ID 4624

Windows Event ID 4624 represents a successful logon.

Query:

```spl
index=* EventCode=4624
| table _time host TargetUserName IpAddress LogonType
```

### Purpose

This can help analysts investigate:

* User authentication
* Login time
* Account involved
* Source IP information
* Logon type

---

### 8.4 Failed Login – Event ID 4625

Windows Event ID 4625 represents a failed logon.

Query:

```spl
index=* EventCode=4625
| stats count by IpAddress TargetUserName
| sort - count
```

### Purpose

This detection can help identify:

* Repeated authentication failures
* Possible password guessing
* Suspicious login attempts
* Accounts receiving multiple failed logons

During final testing, matching 4625 events were not consistently available in the collected dataset.

---

### 8.5 User Added to Security Group – Event ID 4732

Windows Event ID 4732 can be used to identify users added to local security groups.

Query:

```spl
index=* EventCode=4732
| table _time host SubjectUserName MemberName GroupName
```

### Purpose

This detection can help identify:

* Unauthorized group membership changes
* Potential privilege escalation
* Changes to administrative groups

No matching 4732 events were available in the final collected dataset.

---

## 9. SOC Dashboard

A Splunk SOC monitoring dashboard was created to provide a centralized view of endpoint activity.

The dashboard included available monitoring panels such as:

* Total Sysmon Events
* Successful Logins
* Process Creation
* PowerShell Activity

The dashboard provides a basic SOC-style overview that allows an analyst to quickly identify endpoint activity and investigate events.

---

## 10. Investigation Process

The investigation workflow used in this project was:

```text
Event Generated
      ↓
Sysmon / Windows Event Log
      ↓
Splunk Collection
      ↓
SPL Search
      ↓
Event Analysis
      ↓
User / Process / Command Line Analysis
      ↓
Security Investigation
      ↓
MITRE ATT&CK Mapping
```

Important fields used during investigation included:

* Timestamp
* Host
* User
* Process Image
* Command Line
* Parent Process
* Event ID

---

## 11. MITRE ATT&CK Mapping

The PowerShell detection can be mapped to:

**T1059.001 – PowerShell**

**Tactic:** Execution

**Technique:** Command and Scripting Interpreter: PowerShell

PowerShell monitoring is important because attackers may use PowerShell to execute commands and perform malicious actions after gaining access to a system.

---

## 12. Results

The project successfully demonstrated:

* Splunk Enterprise deployment.
* Sysmon installation.
* Sysmon Operational log collection.
* Sysmon and Splunk integration.
* Process creation monitoring.
* PowerShell activity monitoring.
* Windows authentication monitoring.
* SPL detection development.
* SOC dashboard creation.
* MITRE ATT&CK mapping.
* Security event investigation.

The project provided practical experience with the workflow used by SOC analysts to collect, search, investigate, and document endpoint security events.

---

## 13. Challenges Encountered

Several practical issues were encountered during implementation, including:

* Splunk Web interface becoming temporarily unavailable.
* Splunk service stopping unexpectedly.
* Splunk dispatch/file-writing errors.
* Some Windows event types not being available in the collected dataset.
* Dashboard panels showing no results when corresponding events were absent.
* Identifying the correct Sysmon sourcetype.
* Working with different time ranges when searching recent events.

These troubleshooting activities provided practical experience with SIEM deployment and endpoint log analysis.

---

## 14. Limitations

The project was performed in a controlled laboratory environment.

Some security events, such as Event ID 4625 and Event ID 4732, were not consistently present in the collected dataset. Therefore, the corresponding SPL queries were developed and documented, but no claim is made that those events were successfully detected during the final test.

---

## 15. Future Improvements

The project can be expanded by adding:

* Automated Splunk alerts.
* Email or notification-based alerting.
* More Sysmon event types.
* Brute-force detection.
* Privilege escalation detection.
* Advanced PowerShell detection.
* Network monitoring.
* Threat intelligence integration.
* Suricata IDS integration.
* Expanded MITRE ATT&CK coverage.
* Automated incident response.

---

## 16. Conclusion

This project successfully implemented a basic Windows endpoint security monitoring environment using Splunk Enterprise and Microsoft Sysmon.

Sysmon provided detailed endpoint telemetry, while Splunk provided centralized log searching, analysis, visualization, and dashboarding.

The project demonstrates practical skills in:

* SIEM administration
* Windows event monitoring
* Sysmon
* SPL
* Security detection
* SOC investigation
* Dashboard creation
* MITRE ATT&CK mapping

The completed project provides a practical foundation for further development toward SOC Analyst and Security Analyst roles.

---

## 17. Project Evidence

Screenshots documenting the implementation, searches, detections, and dashboard are available in the repository's `screenshots/` directory.

The SPL detection queries are available in the `queries/` directory.

The complete project documentation is maintained in the `report/` directory.


Windows Endpoint Monitoring and Threat Detection Using Splunk and Sysmon
1. Project Overview

This project implements a Windows endpoint monitoring and security event detection environment using Splunk Enterprise and Microsoft Sysmon.

The main objective was to collect Windows endpoint telemetry, forward Sysmon Operational events to Splunk, search and analyze security events using SPL, and develop basic SOC detection capabilities.

The project was performed in a controlled Windows laboratory environment.

2. Objectives

The main objectives of this project were:

Install and configure Splunk Enterprise.
Install and configure Microsoft Sysmon.
Collect Sysmon Operational events.
Integrate Windows Sysmon logs with Splunk.
Analyze process creation events.
Monitor PowerShell activity.
Monitor Windows successful authentication events.
Develop SPL queries for security monitoring.
Create a basic SOC monitoring dashboard.
Analyze endpoint events from a SOC analyst perspective.
Map relevant detections to MITRE ATT&CK techniques.
Document the implementation and findings.
3. Technologies Used
Technology	Purpose
Windows 11	Endpoint/lab environment
Splunk Enterprise	SIEM and log analysis
Microsoft Sysmon	Endpoint telemetry
Windows Event Viewer	Event verification
SPL	Security event searching and analysis
GitHub	Project documentation and portfolio
MITRE ATT&CK	Threat technique mapping
4. Environment

The project was implemented on a Windows endpoint with Splunk Enterprise installed locally.

Log Flow
Windows Endpoint
       |
       v
     Sysmon
       |
       v
Windows Event Log
       |
       v
Splunk Event Log Collection
       |
       v
Splunk Enterprise
       |
       v
SPL Searches / Detections
       |
       v
SOC Dashboard
       |
       v
Security Investigation
5. Splunk Installation and Configuration

Splunk Enterprise was installed and configured on the Windows system.

The Splunk installation directory used during the project was:

E:\Program Files\Splunk

The Splunk Web interface was accessed through:

http://localhost:8000

Splunk was verified by performing searches against the collected Windows event data.

6. Sysmon Installation

Microsoft Sysmon was installed to provide detailed endpoint telemetry.

Sysmon records important activities such as:

Process creation
Process termination
Network connections
File activity
Registry activity
PowerShell-related process activity

The project primarily focused on Sysmon Event ID 1 — Process Creation.

7. Sysmon Operational Log Collection

The following Windows Event Log channel was configured for collection:

Microsoft-Windows-Sysmon/Operational

The corresponding Splunk sourcetype was verified as:

WinEventLog:Microsoft-Windows-Sysmon/Operational

During testing, thousands of Sysmon events were successfully available in Splunk.

This confirmed that the Sysmon-to-Splunk log collection pipeline was functioning correctly.

8. Sysmon and Splunk Integration

Sysmon Operational events were added through Splunk's Windows Event Log collection configuration.

The integration was verified using SPL searches.

Example:

index=default
| stats count by sourcetype
| sort - count

The result showed:

WinEventLog:Microsoft-Windows-Sysmon/Operational

with collected events.

This confirmed that Splunk was successfully receiving Sysmon telemetry.

9. Process Creation Detection

Sysmon Event ID 1 represents process creation.

It provides valuable information for SOC investigations, including:

Process image
Command line
Parent process
User
Computer
Process ID
Timestamp
SPL Query
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time Computer User Image CommandLine ParentImage
Purpose

This query can be used to:

Identify newly created processes.
Investigate suspicious executables.
Examine command-line activity.
Identify parent-child process relationships.
Support endpoint incident investigation.
10. PowerShell Detection

PowerShell is a legitimate Windows administration tool but can also be abused by attackers.

PowerShell process activity was monitored using Sysmon Event ID 1.

SPL Query
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*"
| table _time Computer User Image CommandLine ParentImage
Purpose

The detection helps identify:

PowerShell execution.
The user executing PowerShell.
PowerShell command-line information.
The parent process.
Potentially suspicious PowerShell activity.
11. Windows Authentication Monitoring

Windows authentication events were also investigated.

Successful Login

Windows Event ID 4624 represents a successful logon.

Example SPL query:

index=* EventCode=4624
| table _time host TargetUserName IpAddress LogonType

This can help a SOC analyst investigate:

Which account logged in.
When the login occurred.
Source IP information.
Logon type.
Potentially unusual authentication activity.
12. Failed Login Detection

Windows Event ID 4625 represents a failed logon.

The following query was tested:

index=* EventCode=4625
| stats count by IpAddress TargetUserName
| sort - count

No matching events were available in the collected dataset during testing.

This is an important observation rather than a system failure: a detection query can exist even when no corresponding security event has occurred in the available dataset.

The query can be used in a real SOC environment to identify repeated authentication failures and potential password-guessing activity.

13. Security Group Monitoring

Event ID 4732 was investigated for detecting users added to local security groups.

Example query:

index=* EventCode=4732
| table _time host SubjectUserName MemberName GroupName

No matching events were available in the collected dataset during the final testing period.

The detection remains useful for monitoring unauthorized privilege changes.

14. Splunk SOC Dashboard

A basic SOC monitoring dashboard was created in Splunk.

The dashboard was designed to provide a centralized view of endpoint activity.

The dashboard included available security telemetry such as:

Total Sysmon events
Successful logins
Process creation
PowerShell activity

Some authentication-related panels may show No results found when the corresponding event types are not present in the collected dataset.

This is expected behavior and does not indicate that Splunk is malfunctioning.

15. SOC Investigation Methodology

The following investigation process was used:

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
Identify User / Process / Command Line
      ↓
Determine Whether Activity Is Suspicious
      ↓
Map to MITRE ATT&CK

For process investigations, the following fields were particularly useful:

Timestamp
User
Process image
Command line
Parent image
Computer
Event ID
16. MITRE ATT&CK Mapping

The PowerShell detection developed in this project can be mapped to:

T1059.001 — PowerShell

Tactic: Execution

Technique: Command and Scripting Interpreter: PowerShell

PowerShell monitoring is valuable because attackers can use PowerShell to execute commands, automate actions, download files, perform reconnaissance, and carry out other post-compromise activities.

The Sysmon process creation query provides telemetry that can assist in detecting and investigating this activity.

17. Detection Queries

The main detection queries developed during the project include:

Sysmon Process Creation
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time Computer User Image CommandLine ParentImage
PowerShell Detection
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*"
| table _time Computer User Image CommandLine ParentImage
Successful Login
index=* EventCode=4624
| table _time host TargetUserName IpAddress LogonType
Failed Login Investigation
index=* EventCode=4625
| stats count by IpAddress TargetUserName
| sort - count
Security Group Change
index=* EventCode=4732
| table _time host SubjectUserName MemberName GroupName
18. Results

The project successfully demonstrated:

Successful Splunk Enterprise deployment.
Successful Sysmon installation.
Successful collection of Sysmon Operational events.
Successful integration between Sysmon and Splunk.
Successful analysis of Sysmon Event ID 1.
Successful PowerShell activity detection.
Successful monitoring of Windows successful login events.
Creation of security-focused SPL queries.
Creation of a basic SOC monitoring dashboard.
Application of MITRE ATT&CK mapping to PowerShell activity.

The project provided practical experience with the workflow used by SOC analysts to collect, search, investigate, and document endpoint security events.

19. Screenshots and Evidence

The project screenshots are stored in the GitHub repository under:

screenshots/

Important evidence includes:

Sysmon installation
Sysmon Operational logs
Sysmon events in Splunk
Sysmon Event ID 1
PowerShell detection
Splunk dashboard
Windows authentication events
20. Project Repository Structure

The final GitHub repository is organized as:

SOC-Splunk-Sysmon/
│
├── README.md
│
├── queries/
│   └── SPL detection queries
│
├── screenshots/
│   └── Project evidence
│
└── report/
    └── Splunk_Sysmon_SOC_Project_Report.md
21. Challenges Encountered

During implementation, several troubleshooting issues were encountered, including:

Splunk Web interface temporarily becoming unavailable.
Splunk service stopping unexpectedly.
Splunk file-writing errors.
Different Windows event types not always being available in the collected dataset.
Dashboard panels showing no results when corresponding events were absent.
Identifying the correct Splunk Sysmon sourcetype.

These issues provided practical experience in troubleshooting SIEM deployments and understanding the difference between a broken detection and an event that simply does not exist in the dataset.

22. Conclusion

This project demonstrated the implementation of a basic Windows endpoint security monitoring environment using Splunk Enterprise and Microsoft Sysmon.

Sysmon provided detailed endpoint telemetry, while Splunk enabled centralized searching, analysis, detection, and visualization of the collected events.

The project particularly focused on process creation and PowerShell monitoring, which are important areas of endpoint security monitoring.

The completed environment provides a foundation for further SOC activities such as:

Advanced correlation rules
Alert creation
Threat hunting
Incident response
Network monitoring
Automated detection
Advanced MITRE ATT&CK mapping
23. Future Improvements

Future versions of the project could include:

Integration with Suricata IDS
Automated Splunk alerts
Email/notification-based alerting
More advanced correlation searches
Brute-force detection
Privilege escalation detection
Suspicious PowerShell command detection
Network connection monitoring
Threat intelligence integration
Expanded MITRE ATT&CK coverage
More advanced SOC dashboards

---

Author

Devikrishna R

Cybersecurity Student | SOC Analyst Aspirant

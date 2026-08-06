# Splunk SOC Monitoring Lab - Project Report

## Project Title

Splunk SOC Monitoring Lab using Windows Event Logs

---

## Objective

The objective of this project is to build a Security Operations Center (SOC) monitoring lab using Splunk Enterprise. The project focuses on collecting Windows Event Logs, monitoring security events, creating dashboards, and configuring alerts for security monitoring.

---

## Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 |
| SIEM Platform | Splunk Enterprise |
| Log Source | Windows Event Logs |
| Log Types | Security, System, Application |

---

## Tasks Completed

- Installed Splunk Enterprise
- Configured Windows Event Log collection
- Collected Security, System, and Application logs
- Monitored Windows Security Events
- Created a SOC Monitoring Dashboard
- Configured a security alert for multiple failed login attempts

---

## Windows Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4720 | User Account Created |
| 4732 | User Added to Security Group |

---

## Current Project Status

✅ Splunk Enterprise Installed

✅ Windows Event Logs Configured

✅ Dashboard Created

✅ Alert Created

---

## Future Enhancements

- Install Sysmon
- Configure Sysmon Log Collection
- Create Advanced Detection Rules
- MITRE ATT&CK Mapping
- Process Creation Monitoring
- PowerShell Monitoring
- Incident Response Report

---

## Conclusion

This project demonstrates the implementation of a basic SOC monitoring environment using Splunk Enterprise. Future updates will enhance the project by integrating Sysmon, advanced threat detection, and MITRE ATT&CK mapping.

# Splunk-SOC-Monitoring-Lab
A SOC monitoring lab using Splunk Enterprise to collect and analyze Windows Security Event Logs, build dashboards, and create security alerts.

## Project Overview

This project demonstrates the implementation of a Security Operations Center (SOC) monitoring lab using Splunk Enterprise on Windows 11. The lab collects Windows Security Event Logs, analyzes authentication events, detects security-related activities, and generates alerts through Splunk dashboards.

This project is being developed incrementally to simulate a real-world SOC environment.

---

## Objectives

- Install and configure Splunk Enterprise
- Collect Windows Event Logs
- Monitor authentication events
- Detect user account creation
- Detect security group membership changes
- Build SOC dashboards
- Create security alerts
- Develop practical SIEM skills using Splunk

---

## Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 |
| SIEM | Splunk Enterprise |
| Data Source | Windows Event Logs |
| Log Types | Security, System, Application |

---

## Windows Event IDs Monitored

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4720 | User Account Created |
| 4732 | User Added to Security Group |

---

## Dashboard

Current dashboard includes:

- Successful Logins
- Failed Logins
- New User Account Creation

---

## Alert Created

**Alert Name**

Multiple Failed Login Attempts

Purpose:

Detects multiple Windows failed logon events that may indicate a brute-force attack.

---

## Skills Demonstrated

- Splunk Enterprise
- SIEM Monitoring
- Windows Event Log Analysis
- SPL (Search Processing Language)
- Dashboard Creation
- Alert Configuration
- Security Event Investigation

---

## Project Status

### Completed

- Splunk Enterprise Installation
- Windows Event Log Collection
- Event ID Monitoring
- Dashboard Creation
- Alert Configuration

### Upcoming Enhancements

- Sysmon Integration
- Process Creation Monitoring
- PowerShell Detection
- MITRE ATT&CK Mapping
- Advanced Dashboards
- Incident Response Report

---

## Screenshots

Screenshots are available in the `screenshots/` directory.

---

## Author

**Devikrishna R**

Cybersecurity Student | SOC Analyst Aspirant

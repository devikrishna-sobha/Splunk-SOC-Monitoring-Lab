# Splunk Search Queries

## 1. Successful Logins
```spl
index=* EventCode=4624
```
Purpose:
- Detect successful Windows logins.

---

## 2. Failed Login Attempts
```spl
index=* EventCode=4625
```
Purpose:
- Detect failed login attempts and possible brute-force attacks.

---

## 3. New User Account Created
```spl
index=* EventCode=4720
```
Purpose:
- Detect creation of new Windows user accounts.

---

## 4. User Added to Security Group
```spl
index=* EventCode=4732
| table _time host SubjectUserName MemberName GroupName
Purpose:
Detect users added to privileged groups.
```

## 5. Sysmon Process Creation

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time Computer User Image CommandLine ParentImage

Purpose:

Detect newly created processes.
Identify the process executable and command line.
Identify the parent process responsible for launching it.

## 6. PowerShell Process Detection
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*"
| table _time Computer User Image CommandLine ParentImage

Purpose:

Detect PowerShell process execution.
Investigate the PowerShell command line.
Identify the user and parent process associated with PowerShell activity.

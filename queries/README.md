# Splunk SOC Detection Queries

## 1. Sysmon Event ID 1 – Process Creation

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time Computer User Image CommandLine ParentImage
```

## 2. PowerShell Activity

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell*" OR CommandLine="*PowerShell*"
| stats count
```

## 3. Successful Login – Event ID 4624

```spl
index=* EventCode=4624
| table _time host TargetUserName IpAddress LogonType
```

## 4. Failed Login – Event ID 4625

```spl
index=* EventCode=4625
| stats count by IpAddress TargetUserName
| sort - count
```

## 5. User Added to Security Group – Event ID 4732

```spl
index=* EventCode=4732
| table _time host SubjectUserName MemberName GroupName
```

## 6. Total Sysmon Events

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count
```

## 7. Top Process Executions

```spl
index=default sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats count by Image
| sort - count
```

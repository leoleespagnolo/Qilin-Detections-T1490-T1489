# Qilin: mass service disable or kill

Detects 5 or more distinct services on one host being force-terminated (Event 7034/7031) or set to Disabled (Event 7040) within a roughly 6-minute window. Ransomware such as Qilin stops and disables backup, database, and virtualization services before encryption so their files can be encrypted and recovery fails. This rule does not depend on a specific list of service names.

## Settings

| Setting | Value |
|---|---|
| Rule type | Threshold |
| Index | winlogbeat-* |
| Severity (risk score) | High (73) |
| Building block | No |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by threshold fields, 30m |
| Threshold | group by `host.name`, count >= 1, distinct `winlog.event_data.param1` >= 5 |
| MITRE ATT&CK | Impact (TA0040) > Service Stop (T1489) |
| Tags | `Qilin`, `Ransomware`, `T1489`, `Lab: Winlogbeat`, `Qilin-service-stop` |
| Highlighted fields | `host.name` |

## Query

```kql
winlog.provider_name : "Service Control Manager" and
(event.code : ("7034" or "7031") or
 (event.code : "7040" and winlog.event_data.param3 : "disabled"))
```

## False positives

- Software uninstalls/upgrades (Veeam/SQL Server updates) that stop and disable several of their own services
- Admin maintenance scripts.

## References

- https://www.ahnlab.com/en/contents/content-center/35984
- https://areteir.com/resources/malware-spotlight-qilin-ransomware

## Investigation guide

1.This rule cannot identify who stopped the services; the SCM events carry no actor.
2. Check for “Qilin-style: targeted service disabled” alerts on the same host; 7040 events record the account in winlog.user.name.
3. Search the host for process starts (Sysmon Event 1) in the 10 minutes before the alert. Look for unknown executables, --password in a command line, or net, sc, wmic, taskkill.
4.Check for related activity: vssadmin delete shadows, event log clearing, new services (7045).
5.If services are business-critical (backup, database), treat as a likely ransomware precursor and escalate immediately.
6. Event 7036 isn't logged on the tested Windows 10 build, so polite service stops with no disable or kill are invisible to this rule. This is covered in Rule 3 that covers command-line stops.

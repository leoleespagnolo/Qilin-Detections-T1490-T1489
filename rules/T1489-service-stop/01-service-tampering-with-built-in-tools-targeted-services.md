# Service tampering with built-in tools: targeted services

Detects net, sc, wmic, or taskkill used to stop, disable, or force-kill one of the backup, database, Exchange, virtualization, or security services Qilin targets. This is hands-on operator activity, not the Qilin encryptor, which uses the Service Control Manager API directly and spawns no process. Matches on the target keyword; the same tools against other services are handled by the building-block variant (3b).

## Settings

| Setting | Value |
|---|---|
| Rule type | Event correlation (EQL) |
| Index | winlogbeat-* |
| Severity (risk score) | High (73) |
| Building block | No |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by `host.name`, 10m |
| MITRE ATT&CK | Impact (TA0040) > Service Stop (T1489) |
| Tags | `Qilin`, `Ransomware`, `T1489`, `Lab: Winlogbeat`, `Qilin-service-stop` |
| Highlighted fields | `process.command_line`, `process.pe.original_file_name`, `user.name`, `process.parent.name`, `process.parent.command_line` |

## Query

```eql
process where event.type == "start" and event.module == "sysmon" and (
  (process.pe.original_file_name : ("net.exe", "net1.exe") and process.args : "stop") or
  (process.pe.original_file_name : "sc.exe" and process.args : ("stop", "config")) or
  (process.pe.original_file_name : "wmic.exe" and process.command_line : ("*ChangeStartMode*", "*StopService*")) or
  (process.pe.original_file_name : "taskkill.exe" and process.args : ("/f", "-f"))
) and process.command_line : ("*veeam*", "*backup*", "*gxvss*", "*gxcvd*", "*acronis*",
    "*sql*", "*oracle*", "*msexchange*", "*vmms*", "*vss*", "*sophos*",
    "* qb*", "*'qb*", "*\"qb*",
    "* sap*", "*'sap*", "*\"sap*",
    "*memtas*", "*mepocs*")
```

## Investigation guide

**A built-in Windows tool (net, sc, wmic, or taskkill) was used to stop, disable, or kill one of the services Qilin targets (backup, database, Exchange, virtualization, or security software). This is hands-on-keyboard activity, not the Qilin encryptor itself, which uses the API directly. If this host runs backups or databases, treat it as a possible active intrusion and work it promptly.**

1. **Read the command first:** process.command_line shows exactly what was run and which service it hit. This is the fact the alert turns on, so start here.
2. **Check who and from where:** user.name is the account that ran the command (for Sysmon events, not winlog.user.name, which is SYSTEM). process.parent.name is what launched it. An admin’s interactive powershell.exe or cmd.exe under explorer.exe is routine. A script host (wscript.exe, cscript.exe), an Office app, or an unknown binary in AppData or ProgramData as the parent is not, and raises this toward a real incident.
3. **Rule out the benign explanations:** The likely false positives are vendor installers and updaters reconfiguring their own service mid-upgrade (parent is an MSI or the vendor’s updater), admin maintenance on exactly these services (check for a change ticket or maintenance window), and config-management tooling like SCCM or Ansible (service account, runs on many hosts at once, regular timing). If one of these fits, it’s probably benign.
4. **Pivot to the rest of the host’s activity.** Search Sysmon Event 1 on this host for the 10 minutes before and after: unknown executables, --password or --no-services on a command line, other service tampering. Search for a disabled service: host.name : "<host>" and event.code : "7040" and winlog.event_data.param3 : "disabled".
5. **Check for corroborating alerts:** Look for other Qilin-service-stop alerts on this host, and for shadow copy deletion or event log clearing. A correlation alert (Critical) means a second independent rule already fired here.
6. **Decide:** One command from a known admin account during a ticketed window, with a normal parent process, closes as benign with that reason documented. An unexpected account, an unusual parent, no ticket, or any corroborating alert on the host escalates with the command, the account, the timeline, and the services affected.

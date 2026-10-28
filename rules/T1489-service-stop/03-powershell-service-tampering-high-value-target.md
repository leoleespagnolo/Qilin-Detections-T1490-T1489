# PowerShell service tampering: high-value target

Detects PowerShell cmdlets or CIM methods stopping a service or changing its start type to Disabled or Manual, where the target is a backup, database, mail, virtualization, or security service. These run inside PowerShell without launching a new process, so Sysmon process rules cannot see them; script block logging (4104) captures the code. The same cmdlets against other services are handled by the building-block variant (4104b).

## Settings

| Setting | Value |
|---|---|
| Rule type | Custom query (KQL) |
| Index | winlogbeat-* |
| Severity (risk score) | Low (21) |
| Building block | Yes |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by `host.name`, 10m |
| MITRE ATT&CK | not mapped yet |
| Tags | `Qilin`, `Ransomware`, `T1489`, `T1059.001`, `Lab: Winlogbeat`, `Qilin-service-stop` |
| Highlighted fields | `powershell.file.script_block_text`, `winlog.user.name`, `powershell.file.script_block_id` |

## Query

```kql
event.code : "4104" and
powershell.file.script_block_text : (
  "Stop-Service" or "spsv" or "StopService" or "ChangeStartMode" or "net stop" or
  ("Set-Service" and ("Disabled" or "Stopped")) or
  ("Get-Service" and ".Stop")
) and
powershell.file.script_block_text : (
  *veeam* or *backup* or *gxvss* or *gxcvd* or *acronis* or *sql* or *oracle* or
  *msexchange* or vmms or vss or *sophos* or qb* or sap* or memtas or mepocs
)
```

## Investigation guide

**A PowerShell cmdlet or CIM method stopped, disabled, or set to Manual one of the backup, database, mail, virtualization, or security services Qilin targets. Because this runs inside PowerShell and spawns no process, Sysmon process rules (Rule 3) are blind to it; only script block logging sees it. If this host runs backups or databases, treat it as possible active intrusion and work it promptly.**

1. **Read the code that ran.** `powershell.file.script_block_text` is the exact command, including the cmdlet and the target service. This is the fact the alert turns on, so start here. Note that 4104 logs what was run, not whether it succeeded, so a `-WhatIf` dry run or a failed command still fires; confirm the service actually changed with a 7040 or 7034 event.

2. **Read the full script if it was split.** Long scripts are logged across several 4104 events. If `powershell.total` is greater than 1, search the same `powershell.file.script_block_id` to reassemble the whole script before judging it.

3. **Check who and how.** `winlog.user.name` is the account that ran it (for PowerShell events the actor is here, not `user.name`). Decide whether the code ran interactively in a session or from a script file, and whether that account and that activity are expected on this host.

4. **Rule out the benign explanations.** Admin maintenance scripts, vendor upgrade scripts, and PowerShell modules whose own source contains these cmdlets can all trip this. A module loading its source is the sneakiest false positive: the code appears in the log without anyone running it. Check whether the script_block_text is a real invocation or a function definition inside a loaded module.

5. **Pivot and corroborate.** Search this host for other Qilin-service-stop alerts, for a disabled service

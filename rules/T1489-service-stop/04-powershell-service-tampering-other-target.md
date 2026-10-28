# PowerShell service tampering: other target

Detects PowerShell cmdlets or CIM methods stopping a service or changing its start type to Disabled or Manual, where the target is a backup, database, mail, virtualization, or security service. These run inside PowerShell without launching a new process, so Sysmon process rules cannot see them; script block logging (4104) captures the code

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
) and not
powershell.file.script_block_text : (
  *veeam* or *backup* or *gxvss* or *gxcvd* or *acronis* or *sql* or *oracle* or
  *msexchange* or vmms or vss or *sophos* or qb* or sap* or memtas or mepocs
)
```

## Investigation guide

_Not written yet._

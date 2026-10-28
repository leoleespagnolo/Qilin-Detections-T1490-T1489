# Shadow copy deletion

Detects deletion of volume shadow copies, shrinking of shadow storage to evict them, or disabling of Windows recovery, via vssadmin, wmic, PowerShell (Win32_ShadowCopy), wbadmin, diskshadow, or bcdedit. Ransomware including Qilin removes shadow copies before or during encryption so victims cannot restore from Previous Versions. Matches on the recovery-inhibiting action regardless of which tool is used, including the vssadmin resize path that destroys copies without a delete command.

## Settings

| Setting | Value |
|---|---|
| Rule type | Event correlation (EQL) |
| Index | winlogbeat-* |
| Severity (risk score) | High (73) |
| Building block | No |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by `host.name`, `process.command_line`, 10m |
| MITRE ATT&CK | Impact (TA0040) > Inhibit System Recovery (T1490) |
| Tags | `Qilin`, `Ransomware`, `T1490`, `Lab: Winlogbeat` |

## Query

```eql
process where event.type == "start" and event.module == "sysmon" and
(
  (process.pe.original_file_name : "VSSADMIN.EXE" and process.args : ("delete", "resize") and process.args : ("shadows", "shadowstorage")) or
  (process.pe.original_file_name : "WMIC.exe" and process.command_line : "*shadowcopy*" and process.command_line : "*delete*") or
  (process.pe.original_file_name : "PowerShell.EXE" and process.command_line : "*Win32_ShadowCopy*" and process.command_line : "*Delete*") or
  (process.pe.original_file_name : "wbadmin.exe" and process.args : "delete") or
  (process.pe.original_file_name : "diskshadow.exe" and process.command_line : "*delete*") or
  (process.pe.original_file_name : "bcdedit.exe" and process.command_line : ("*recoveryenabled*no*", "*bootstatuspolicy*ignoreallfailures*"))
)
```

## Investigation guide

**A tool was run to delete volume shadow copies, shrink shadow storage to evict them, or disable Windows recovery (vssadmin, wmic, PowerShell, wbadmin, diskshadow, or bcdedit). This is Inhibit System Recovery, the step ransomware takes so victims cannot restore from backups or Previous Versions. On a workstation or server this is rarely legitimate and it usually happens immediately before or during encryption. Treat it as a likely active ransomware event and escalate without waiting.**

1. **Read the exact command.** `process.command_line` shows precisely what ran and which recovery path it destroyed. This is the fact the alert turns on. Match it to the branch: vssadmin delete/resize, wmic shadowcopy delete, PowerShell Win32_ShadowCopy, wbadmin delete, diskshadow delete, or bcdedit disabling recovery.

2. **Note which recovery path was hit.** Each tool removes a different safety net: vssadmin and diskshadow and wmic and PowerShell target shadow copies; wbadmin targets Windows Backup; bcdedit turns off automatic repair. Several different tools on one host means the attacker is closing every recovery route, which is a strong ransomware signal.

3. **Identify who and what launched it.** `user.name` is the account; `process.parent.name` is what spawned the tool. A script, an unknown binary, or a non-admin shell as parent raises suspicion. An interactive admin shell during known maintenance lowers it, but see step 5 before closing on that alone.

4. **Assume encryption is imminent or underway.** Unlike the service rules, this action has no "takes effect later" delay; the recovery path is gone the moment the command runs. Check the host now for mass file writes or modifications, new ransom-note files, and wallpaper or extension changes. If encryption is in progress, containment (isolate the host) comes before further investigation.

5. **Rule out the narrow benign cases.** Backup software pruning old restore points, admin disk cleanup, and legitimate backup rotation can run wbadmin delete or vssadmin resize. These are the only realistic false positives, and they should tie to a backup product, a scheduled job, or a documented admin task. A bare `vssadmin delete shadows /all /quiet` from an interactive session is almost never benign.

6. **Pivot and corroborate.** Search this host for Qilin-service-stop alerts, event log clearing, and service disables in the surrounding minutes. A correlation alert on the host, or shadow copy deletion alongside disabled backup services, is a near-certain ransomware sequence.

7. **Decide.** Close as benign only with a specific, documented cause (a named backup product's rotation, a ticketed cleanup). Anything else escalates immediately, with the command, the recovery path destroyed, the account, and whatever encryption evidence you found. When unsure, escalate; the cost of a late ransomware call is the whole environment.

# Service tampering via built-in tools: other target

Building block. Detects net, sc, wmic, or taskkill used to stop, disable, or force-kill a service that is NOT on the Qilin high-value target list. On its own this is usually benign admin activity, so it does not alert; it is recorded and feeds the correlation rule, which escalates when a second Qilin-service-stop signal fires on the same host within the window.

## Settings

| Setting | Value |
|---|---|
| Rule type | Event correlation (EQL) |
| Index | winlogbeat-* |
| Severity (risk score) | Low (21) |
| Building block | Yes |
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
) and not process.command_line : ("*veeam*", "*backup*", "*gxvss*", "*gxcvd*", "*acronis*",
    "*sql*", "*oracle*", "*msexchange*", "*vmms*", "*vss*", "*sophos*",
    "* qb*", "*'qb*", "*\"qb*",
    "* sap*", "*'sap*", "*\"sap*",
    "*memtas*", "*mepocs*")
```

## Investigation guide

**This is a building-block alert and does not page on its own. It records a built-in tool (net, sc, wmic, or taskkill) stopping, disabling, or killing a service that is not on the Qilin high-value list. In isolation this is almost always benign admin activity. You are most likely seeing it because a correlation alert on this host led you here, or because you are auditing the rule.**

1. **Check why it surfaced.** If you reached this from a correlation alert, the 3b hit is one of the two-or-more signals that escalated. Treat the correlation alert as the real alert and use this one as supporting detail: what else happened on the host.

2. **Read the command and the actor.** `process.command_line` is what ran; `user.name` is who ran it (not `winlog.user.name`, which is SYSTEM for Sysmon events); `process.parent.name` is what launched it. A normal interactive shell under explorer.exe is routine. A script host or an unknown binary as parent is the thing that makes an otherwise-boring service stop worth a second look.

3. **Consider whether the target should have been high-value.** 3b fires on services not matched by the keyword list. If the command targeted something that is a backup, database, or security service but is named in a way the list missed, that is a tuning gap, not a benign event. Note the service name so the keyword list can be widened and the next occurrence lands in 3a.

4. **Do not escalate on this alert alone.** Close it or leave it as context. If it is the only signal on the host, it is noise by

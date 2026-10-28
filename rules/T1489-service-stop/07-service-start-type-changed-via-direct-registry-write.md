# Service start type changed via direct registry write

Detects a service’s Start value set to Disabled (4), or a backup, database, mail, virtualization, or security service set to Manual (3), by writing the registry directly rather than through the Service Control Manager. A direct write changes the service without going through the SCM, so no 7040 is logged and Rules 1 and 2 are blind to it; Sysmon Event 13 records the write. Writes by services.exe are excluded, since that is the SCM making the same change the normal way.

## Settings

| Setting | Value |
|---|---|
| Rule type | Event correlation (EQL) |
| Index | winlogbeat-* |
| Severity (risk score) | High (73) |
| Building block | No |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by `host.name`, `registry.path`, per rule execution |
| MITRE ATT&CK | not mapped yet |
| Tags | `Qilin`, `Ransomware`, `T1489`, `T1112`, `Lab: Winlogbeat`, `Qilin-service-stop` |
| Highlighted fields | `registry.path`, `registry.data.strings`, `process.name`, `process.executable`, `user.name` |

## Query

```eql
registry where event.module == "sysmon" and event.code == "13" and
  registry.path : "HKLM\\System\\*ControlSet*\\Services\\*\\Start" and
  not process.name : "services.exe" and
  (
    registry.data.strings : "4" or
    (registry.data.strings : "3" and
     registry.path : ("*veeam*", "*backup*", "*\\gx*", "*acronis*", "*sql*", "*oracle*",
                      "*msexchange*", "*\\vmms\\*", "*\\vss\\*", "*sophos*", "*\\qb*",
                      "*\\sap*", "*memtas*", "*mepocs*"))
  )
```

## Investigation guide

**A service's Start value was written directly in the registry, setting it to Disabled (4), or to Manual (3) for a service Qilin targets. This bypasses the Service Control Manager, so no 7040 is logged and the SCM-based rules never see it; Sysmon Event 13 is the only record. A direct registry write to a service's start type is unusual on its own and is a known ransomware evasion. If this host runs backups or databases, treat it as a possible active intrusion and work it promptly.**

1. **Read what was written and by what.** `registry.path` ends in the service's key name, so it tells you which service; `registry.data.strings` is the value (4 = Disabled, 3 = Manual). `process.name` and `process.executable` are what made the write (`reg.exe`, `powershell.exe`, or something else). `user.name` is the account.

2. **Judge the writer.** services.exe is excluded by the rule, so whatever you see here is NOT the SCM making a normal change. `reg.exe` or `powershell.exe` writing a service Start value is the attacker's way around 7040. An unknown or unexpected binary as the writer is stronger still.

3. **Confirm the effect, and note the timing.** A registry write to Start does not take effect until the service next starts or the host reboots, so the service may still be running now. Do not treat "service still up" as evidence this was benign. Pair it with a forced stop or a kill on the same host, which is how the change is made to bite immediately.

4. **See the full picture on the host.** Search every service Start write on this host: `host.name : "<host>" and event.code : "13" and registry.path : *Services*Start`. Several in a short window is a burst and points to automated tampering.

5. **Rule out the benign explanations.** Software installers and uninstallers, and admins hardening or decommissioning a service, can write Start directly. Check the writer process and the account against a change ticket or maintenance window. An MSI or vendor updater is more likely benign than an interactive shell or an unknown binary.

6. **Pivot and corroborate.** Search Sysmon Event 1 on this host for the surrounding minutes: unknown executables, net/sc/wmic/taskkill, or `--password` / `--no-services` on a command line. Look for other Qilin-service-stop alerts, shadow copy deletion, or event log clearing. A correlation alert (Critical) means a second independent rule already fired here.

7. **Decide.** A known admin account or an installer during a ticketed window closes as benign with that reason recorded. An unexpected account, an unknown writer process, a protected service, a burst of writes, or any corroborating alert on the host escalates with the service, the value written, the writer, and the timeline.

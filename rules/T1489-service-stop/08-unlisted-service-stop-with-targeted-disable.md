# Qilin: unlisted service stop with targeted disable

Identifies a host where a targeted backup, database, or security service was disabled and a built-in tool (sc.exe, net.exe, taskkill.exe, or wmic.exe) stopped an additional, unlisted service within 15 minutes, in either order. Qilin and other ransomware operators disable recovery and security services before encryption, then stop further services to release file locks. Either activity alone occurs during routine administration; together on one host in a short window, they match pre-encryption preparation. This rule raises confidence and priority on hosts that already triggered the targeted-disable rule; it does not add independent coverage.

## Settings

| Setting | Value |
|---|---|
| Rule type | ES|QL |
| Index | `FROM` clause in query |
| Severity (risk score) | High (85) |
| Building block | No |
| Schedule | every 5m, look-back from `now-15m` |
| Timestamp override | none |
| Alert suppression | by `host.name`, 30m |
| MITRE ATT&CK | Impact (TA0040) > Service Stop (T1489) |
| Tags | `Qilin`, `T1489`, `Tactic: Impact`, `Rule Type: Correlation` |
| Highlighted fields | `host.name`, `process.command_line`, `user.name`, `event.start`, `event.end` |

## Query

```esql
FROM .alerts-security.alerts-default
| WHERE kibana.alert.rule.name IN (
    "Qilin: targeted service disabled",
    "Service tampering via built-in tools: other target"
  )
  AND host.name IS NOT NULL
| STATS
    rule_count = COUNT_DISTINCT(kibana.alert.rule.name),
    event.start = MIN(kibana.alert.original_time),
    event.end = MAX(kibana.alert.original_time),
    user.name = VALUES(user.name),
    process.command_line = VALUES(process.command_line)
  BY host.name
| WHERE rule_count == 2 AND DATE_DIFF("minute", event.start, event.end) <= 15
```

## False positives

- Software uninstallers, which commonly disable a product’s service and stop its helper services.
- Patching or upgrade windows for backup, database, or security products.
- Administrators decommissioning a server.

## Investigation guide

**A targeted backup, database, or security service was disabled (Event 7040) and a built-in tool (net, sc, wmic, or taskkill) stopped an unlisted service on the same host within 15 minutes, in either order. Either action alone is routine administration; together they match ransomware preparing a host for encryption by keeping recovery services down and releasing file locks. This alert always accompanies a "Qilin: targeted service disabled" alert. It exists to raise that alert's priority. Work it promptly.**

1. **Read the evidence on this alert first.** `process.command_line` lists what the built-in tools ran; `user.name` lists who ran them; `event.start` and `event.end` show how tight the window was. Two minutes apart reads differently from fourteen.

2. **Open both source alerts.** On "Qilin: targeted service disabled," `winlog.event_data.param1` is the disabled service and `winlog.user.name` is the account (7040 records the actor there, not in `user.name`). On "Service tampering via built-in tools: other target," `process.parent.name` is what launched the tool.

3. **Compare the accounts.** The same account behind both actions means one actor working through a list. Different accounts are weaker evidence, unless one of them is unexpected on this host.

4. **Judge the launcher.** A software installer, vendor updater, or deployment agent as parent suggests an upgrade or uninstall stopping its own services. cmd.exe or powershell.exe from an interactive or remote session, a script host, or an unknown binary is suspicious.

5. **Rule out the benign explanations.** Uninstallers disable a product's main service and stop its helpers, which matches this rule exactly. Check whether the disabled and stopped services belong to the same product, and look for a change ticket or maintenance window covering this host.

6. **Pivot and corroborate.** Search Sysmon Event 1 on this host for the 10 minutes before `event.start`: unknown executables, `--password` or `--no-services` on a command line. Look for "Qilin: mass service disable or kill," shadow copy deletion, event log clearing (1102), or new services (7045).

7. **Decide.** One product's own services during a ticketed upgrade, by a known account, closes as benign with that reason recorded. Unrelated services, an unexpected account or launcher, no ticket, or any corroborating alert escalates immediately with both accounts, the services affected, and the timeline.

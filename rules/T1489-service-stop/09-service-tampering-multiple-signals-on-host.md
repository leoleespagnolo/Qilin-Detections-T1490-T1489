# Qilin service tampering: multiple signals on host

Fires when two or more different Qilin service-tampering rules alert on the same host within 5 minutes. Combines strong signals (mass disable or kill, targeted disable, registry writes, high-value tool or PowerShell use) with building block signals (tool or PowerShell use on other services) to escalate likely ransomware preparation. Counts alerts tagged Qilin-service-stop.

## Settings

| Setting | Value |
|---|---|
| Rule type | Threshold |
| Index | .alerts-security.alerts-default |
| Severity (risk score) | Critical (99) |
| Building block | No |
| Schedule | every 5m, look-back from `now-10m` |
| Timestamp override | none |
| Threshold | group by `host.name`, count >= 2, distinct `kibana.alert.rule.name` >= 2 |
| MITRE ATT&CK | not mapped yet |
| Tags | `Qilin`, `Correlation` |
| Highlighted fields | `host.name` |

## Query

```kql
kibana.alert.rule.tags : "Qilin-service-stop"
```

## Investigation guide

_Not written yet._

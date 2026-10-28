# Qilin: targeted service disabled

Detects a backup, database, mail, virtualization, or security service having its start type changed to Disabled or Manual (Event 7040). Qilin disables these services before encryption so they cannot restart and recovery fails; it also sets VSS to Manual as an intermediate step before deleting shadow copies, which is why Manual is included. Keyword patterns are category-based, so reconfigured builds still match.

## Settings

| Setting | Value |
|---|---|
| Rule type | Event correlation (EQL) |
| Index | winlogbeat-* |
| Severity (risk score) | High (73) |
| Building block | No |
| Schedule | every 5m, look-back from `now-6m` |
| Timestamp override | `event.ingested` |
| Alert suppression | by `host.name`, `winlog.event_data.param4`, 30m |
| MITRE ATT&CK | Impact (TA0040) > Inhibit System Recovery (T1490) |
| Tags | `Qilin`, `Ransomware`, `T1489`, `T1490`, `Lab: Winlogbeat`, `Qilin-service-stop` |
| Highlighted fields | `winlog.event_data.param4`, `winlog.event_data.param1`, `winlog.event_data.param3`, `winlog.user.name` |

## Query

```eql
any where event.code == "7040" and
  winlog.provider_name == "Service Control Manager" and
  (winlog.event_data.param3 : "disabled" or
   (winlog.event_data.param2 : "auto start" and winlog.event_data.param3 : "demand start")) and
  winlog.event_data.param4 : ("*veeam*", "*backup*", "gx*", "*acronis*", "acrsch2svc",
    "pdvfsservice", "vsnapvss", "*sql*", "*oracle*", "msexchange*", "wsbexchange",
    "vmms", "vss", "*sophos*", "qb*", "sap*", "mepocs", "memtas")
```

## False positives

- Vendor upgrades or uninstalls disabling their own services
- Admins decommissioning software

## Investigation guide

**A service Qilin typically targets (backup, database, mail, virtualization, or security software) had its start type changed to Disabled or Manual, logged by the Service Control Manager as Event 7040. Disabling or demoting these services is how Qilin keeps them from restarting during encryption. If this host runs backups or databases, treat it as a possible ransomware precursor and work it promptly; encryption can follow within minutes.**

1. **Identify the account.** `winlog.user.name` is the account that made the change. This is the strongest single signal in the alert and the one field Rules 1 and the SCM-based rules cannot give you. An unexpected or service account here is a strong lean toward malicious.

2. **Read what changed.** `winlog.event_data.param4` is the service key name that matched the list; `param1` is its display name; `param3` is the new start type (disabled or demand start). Confirm the service is actually business-critical, not a same-named service that happens to match a keyword.

3. **See the full picture on the host.** Search every service changed on this host: `host.name : "<host>" and event.code : "7040" and winlog.event_data.param3 : ("disabled", "demand start")`. One service is worth a look; several in a short window is a burst and likely an attack.

4. **Rule out the benign explanations.** Vendor installers and uninstallers disabling their own services during an upgrade, and admins decommissioning software, are the realistic false positives. Check the account against known admins and look for a change ticket or maintenance window. A vendor updater or MSI as the actor is more likely benign than an unexpected interactive account.

5. **Pivot and corroborate.** Search Sysmon Event 1 on this host for the 10 minutes before: unknown executables, `--password` or `--no-services` on a command line, or net/sc/wmic/taskkill use. Look for other Qilin-service-stop alerts, shadow copy deletion, or event log clearing on the same host. A correlation alert (Critical) means a second independent rule already fired here.

6. **Decide.** A known admin account during a ticketed window, or a vendor upgrade, closes as benign with that reason recorded. An unexpected account, a protected service with no maintenance explanation, a burst of disables, or any corroborating alert on the host escalates with the service list, the account, and the timeline.

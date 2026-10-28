# Known gaps and open issues

## Open issues

**1. "Multiple signals on host" can reach Critical on a single action.** The rule counts distinct rule names, but several layers observe the same action. One `sc.exe config <svc> start= disabled` on a listed service fires both "built-in tools: targeted" and "targeted service disabled," which meets the threshold. Two building blocks alone can also meet it. Planned fix: an ES|QL rule that groups rules into families (targeted, mass, registry, other), so one action counts once, and requires at least one non-building-block alert. It would also cover what "unlisted stop with targeted disable" detects, allowing that rule to be retired.

**2. Incomplete MITRE mappings.** The PowerShell and registry rules have technique tags but no ATT&CK mapping in the rule settings, so they do not appear in Elastic's MITRE coverage view. "Targeted service disabled" is mapped to T1490 but not T1489.

**3. Documentation drift on the PowerShell rules.** Their descriptions still mention Manual, which the queries no longer match. The high-value rule's guide was written for a standalone alert and predates its move to building block. The other-target rule has no investigation guide.

## Telemetry limits

- **Event 7036 is not logged** on the tested Windows 10 build. Clean service stops with no disable and no forced termination are visible only through the command layer.
- **The encryptor uses the Service Control Manager API directly.** It spawns no `sc.exe` or PowerShell, so command-layer rules see only hands-on operator activity. The configuration and termination layers cover the encryptor.
- **Event strings are localized.** Values such as `disabled` and `auto start` in 7040 are English. Non-English Windows builds need translated values.

## Rule logic limits

- **4104 matches on co-occurrence.** A stop command and a target name anywhere in the same script block match, even if the command targeted another service. Both PowerShell rules are building blocks for this reason.
- **Large scripts are split across several 4104 events.** If the command and the target land in different parts, neither event matches.
- **4104 records code, not outcomes.** A failed command or a `-WhatIf` run still matches.
- **.NET method calls** such as `(Get-Service x).Stop()` are matched only broadly, and heavy obfuscation can hide cmdlet names entirely.
- **Correlation rules reference source rules by exact name.** Renaming a source rule breaks them without any error.
- **The target list is maintained in three spellings** (typed names, service key names, display names). A service added to one rule and not the others is covered in one layer and missed in the rest.
- **Leading wildcards** (`*veeam*`) on the 4104 text field are fine at lab scale but expensive across millions of script blocks.

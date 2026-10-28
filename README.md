# Qilin detections: service stop (T1489) and inhibit system recovery (T1490)

Elastic Security detection rules for two pre-encryption behaviors of the Qilin (Agenda) ransomware: stopping and disabling backup, database, and security services ([T1489](https://attack.mitre.org/techniques/T1489/)), and destroying recovery options such as volume shadow copies ([T1490](https://attack.mitre.org/techniques/T1490/)).

Built and tested in a home lab as part of a team APT research project. Scope starts after initial access: these rules target what the operator and the encryptor do on a host once they are in.

## Why these behaviors

Before Qilin encrypts, it stops services that hold files open (databases, mail, virtualization) and disables services that would let a victim recover (backup agents, Volume Shadow Copy). It then deletes shadow copies. Both steps happen minutes before encryption, so a reliable detection here is one of the last points where a defender can still contain the host.

## Rules

| Rule | Data source | Type | Severity (risk) | Building block |
|---|---|---|---|---|
| [Service tampering with built-in tools: targeted services](rules/T1489-service-stop/01-service-tampering-with-built-in-tools-targeted-services.md) | Sysmon 1 | Event correlation (EQL) | High (73) | No |
| [Service tampering via built-in tools: other target](rules/T1489-service-stop/02-service-tampering-via-built-in-tools-other-target.md) | Sysmon 1 | Event correlation (EQL) | Low (21) | Yes |
| [PowerShell service tampering: high-value target](rules/T1489-service-stop/03-powershell-service-tampering-high-value-target.md) | PowerShell 4104 | Custom query (KQL) | Low (21) | Yes |
| [PowerShell service tampering: other target](rules/T1489-service-stop/04-powershell-service-tampering-other-target.md) | PowerShell 4104 | Custom query (KQL) | Low (21) | Yes |
| [Qilin: targeted service disabled](rules/T1489-service-stop/05-targeted-service-disabled.md) | System 7040 | Event correlation (EQL) | High (73) | No |
| [Qilin: mass service disable or kill](rules/T1489-service-stop/06-mass-service-disable-or-kill.md) | System 7034, 7031, 7040 | Threshold | High (73) | No |
| [Service start type changed via direct registry write](rules/T1489-service-stop/07-service-start-type-changed-via-direct-registry-write.md) | Sysmon 13 | Event correlation (EQL) | High (73) | No |
| [Qilin: unlisted service stop with targeted disable](rules/T1489-service-stop/08-unlisted-service-stop-with-targeted-disable.md) | Alerts index | ES|QL | High (85) | No |
| [Qilin service tampering: multiple signals on host](rules/T1489-service-stop/09-service-tampering-multiple-signals-on-host.md) | Alerts index | Threshold | Critical (99) | No |
| [Shadow copy deletion](rules/T1490-inhibit-recovery/01-shadow-copy-deletion.md) | Sysmon 1 | Event correlation (EQL) | High (73) | No |

Every rule's query, settings, false positives, and investigation guide are in [`rules/`](rules/). [`rules/elastic-rules-export.ndjson`](rules/elastic-rules-export.ndjson) is the import-ready export of all ten.

## Design in one paragraph

A service kill leaves evidence in more than one place: the command that requested it (Sysmon process creation, PowerShell script block logging), the configuration change that keeps the service down (Event 7040, registry Start value), and the Service Control Manager recording a forced termination (7034, 7031). Each layer covers a blind spot in the others; the Qilin encryptor calls the Service Control Manager API directly and spawns no process, so process-based rules never see it, while the SCM and registry rules do. Severity follows each event's benign base rate: actions that happen during routine administration are building blocks, and correlation rules escalate when independent signals land on the same host. See [`docs/architecture.md`](docs/architecture.md).

## Lab environment

| Component | Detail |
|---|---|
| SIEM | Elastic Stack via [docker-elk](https://github.com/deviantony/docker-elk), Elastic Security detection engine |
| Endpoint | Windows 10 VM (VirtualBox) |
| Shipping | Winlogbeat: Security, System, Sysmon, PowerShell Operational channels |
| Telemetry | Sysmon (process creation, registry), PowerShell script block logging (4104) |
| Emulation | Atomic Red Team T1489 and T1490 tests, plus fake lab services named after Qilin's target list |

System Event 7036 (service entered stopped state) is not logged on the tested build, so no rule depends on it. See [`docs/known-gaps.md`](docs/known-gaps.md).

## Testing

Every rule has a true-positive test and at least one benign test. The matrix, including the ordering and false-positive cases raised in mentor review, is in [`docs/testing.md`](docs/testing.md).

## Importing

1. In Kibana, open **Security > Rules > Detection rules (SIEM)**.
2. Choose **Import rules** and select `rules/elastic-rules-export.ndjson`.
3. Check the index patterns match your environment. The source rules read `winlogbeat-*`; the correlation rules read `.alerts-security.alerts-default`.
4. The correlation rules reference source rules **by exact name**. Renaming a source rule silently breaks them.

## Status

Lab-tested, not production-tested. Open issues, including a known false-positive path in the Critical correlation rule and incomplete MITRE mappings, are tracked in [`docs/known-gaps.md`](docs/known-gaps.md).

## Credits

Team APT research project, mentored by Mike Small. Rules written by Leo Lee-Spagnolo. Shadow copy deletion rule based on Johann's T1490 write-up. <!-- confirm names and credit wording with the team before publishing -->

## References

- MITRE ATT&CK: [T1489 Service Stop](https://attack.mitre.org/techniques/T1489/), [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- AhnLab, Qilin analysis: https://www.ahnlab.com/en/contents/content-center/35984
- Arete, Qilin malware spotlight: https://areteir.com/resources/malware-spotlight-qilin-ransomware

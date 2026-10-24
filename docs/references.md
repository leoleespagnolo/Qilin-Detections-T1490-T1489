# References

Threat intelligence and documentation the rule set is built on.

## Qilin / Agenda analysis

- **AhnLab — Qilin Ransomware: Why Decryption Is Impossible by Design.**
  Source of the service and process kill lists, the VSS
  Manual-then-delete-then-Disabled sequence, and the argument table
  (`--no-proc`, `--no-services`, etc.).
  https://www.ahnlab.com/en/contents/content-center/35984

- **Cisco Talos — Uncovering Qilin attack methods.** Operator tradecraft,
  PsExec spread, per-victim configuration including hardcoded credentials in
  one observed config.
  https://blog.talosintelligence.com/uncovering-qilin-attack-methods-exposed-through-multiple-cases/

- **Arete — Malware Spotlight: Qilin Ransomware.**
  https://areteir.com/resources/malware-spotlight-qilin-ransomware

## MITRE ATT&CK

- **T1489 — Service Stop.** https://attack.mitre.org/techniques/T1489/
- **T1490 — Inhibit System Recovery.** https://attack.mitre.org/techniques/T1490/
- **T1112 — Modify Registry.** https://attack.mitre.org/techniques/T1112/
- **T1059.001 — Command and Scripting Interpreter: PowerShell.**
  https://attack.mitre.org/techniques/T1059/001/

## Tooling

- **Atomic Red Team** (Red Canary) — independent technique tests for T1489 and
  T1490. https://github.com/redcanaryco/atomic-red-team
- **Sysmon** (Microsoft Sysinternals).
- **olafhartong/sysmon-modular** — Sysmon configuration.
  https://github.com/olafhartong/sysmon-modular

## A note on the kill lists

The service and process lists published by AhnLab come from a single analyzed
Qilin build. Qilin's configuration lets each affiliate define the target
substrings and regular expressions per victim, so these lists are accurate for
that sample but are **not** a master list. The rules key on categories and
substrings rather than exact names, and Rule 1 is list-independent, precisely
because the names change between victims.

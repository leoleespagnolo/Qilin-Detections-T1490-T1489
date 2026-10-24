# Lab setup

How to reproduce the telemetry pipeline these rules run on. The goal is a
Windows endpoint shipping Sysmon, PowerShell, and Windows Security events into
Elastic, where the detection rules evaluate them.

## Architecture

```
Windows VM (sensor)                 Host PC (SIEM)
  Sysmon          ─┐
  PowerShell SBL   ├─ Winlogbeat ──► Elasticsearch ──► Kibana (detection rules)
  Windows Security ┘                 (docker-elk)
```

- **VM:** VirtualBox, NAT networking, Windows 10 (build 19045). Hostname
  `w10-lab`, reachable to the host at `10.0.2.2`.
- **Host:** docker-elk running Elastic Stack 9.x, Kibana on `localhost:5601`,
  Elasticsearch on `localhost:9200`.
- **Data view:** `winlogbeat-*`.

## Endpoint configuration

### Sysmon

Install with a maintained config (process, registry, network, and other
events). Either works:

- olafhartong/sysmon-modular
  (`https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml`)
- SwiftOnSecurity/sysmon-config

The registry rule depends on Sysmon logging Event 13 for writes under
`Services\*\Start`. Confirm the config does not filter those out before relying
on that rule.

### PowerShell script block logging

Required for the 4104 rules. Enable via registry or GPO:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
  EnableScriptBlockLogging = 1 (DWORD)
```

Script block logging only applies to **new** PowerShell sessions, so open a
fresh window after enabling.

### Winlogbeat

Install Winlogbeat matching your Elastic version, point it at the host's
Elasticsearch, and ship the Sysmon, PowerShell, and Security channels.

## Gotchas hit during the build

Recorded because they cost real time and the official docs don't flag them.

- **Download large files with `curl.exe`, not `Invoke-WebRequest`.** `IWR` threw
  an EOF error on large installers inside the VM; `curl.exe` completed cleanly.
- **Execution policy blocks install scripts.** Set it for the process scope
  (`Set-ExecutionPolicy Bypass -Scope Process`) before running Sysmon or Atomic
  installers.
- **Editing the wrong line in `winlogbeat.yml`.** A YAML indentation error came
  from editing the Logstash `hosts:` line instead of the Elasticsearch one.
  Edit the Elasticsearch output block.
- **Ingestion delay is real.** Events took roughly 40 seconds to 5 minutes to
  reach Elasticsearch. Every raw-event rule uses the `event.ingested` timestamp
  override with a 1-minute additional look-back to cover it. The correlation and
  composition rules, which read the alerts index, must **not** use the override;
  they order on `@timestamp`.
- **SCM caches the `Start` value.** A direct registry write to `Start` is not
  applied by the running Service Control Manager until the service restarts or
  the host reboots. Use `Set-Service` to reset services between tests.

## Lab test services

To exercise the rules without real backup/database software, compile a
do-nothing service and register it under names from the kill list:

```powershell
$code = @"
using System.ServiceProcess;
public class LabSvc : ServiceBase {
  protected override void OnStart(string[] args) {}
  protected override void OnStop() {}
  public static void Main() { ServiceBase.Run(new LabSvc()); }
}
"@
Add-Type -TypeDefinition $code -ReferencedAssemblies System.ServiceProcess `
  -OutputAssembly C:\Tools\LabSvc.exe -OutputType ConsoleApplication

$names = "VeeamTransportSvc","BackupExecJobEngine","SQLLabSvc","MSExchangeLab","GxVss","memtas"
foreach ($n in $names) {
  New-Service -Name $n -BinaryPathName "C:\Tools\LabSvc.exe" -StartupType Automatic
  Start-Service $n
}
```

Reset between tests:

```powershell
foreach ($n in $names) { Set-Service $n -StartupType Automatic; Start-Service $n }
```

## Atomic Red Team

For independent validation. **Snapshot the VM first**, since T1490 tests delete
real shadow copies.

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Defender will flag the test files; add an exclusion for `C:\AtomicRedTeam` in the
lab VM only. Run tests one at a time with `-TestNumbers`, and wait ~10 minutes
between runs so suppression and the correlation window clear.

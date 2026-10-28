# Testing

Tests run on the lab Windows 10 VM against fake services named after Qilin's target list (`<LabSvc>` below), plus Atomic Red Team T1489 and T1490 tests. Each rule has a true-positive test and at least one benign test that must **not** fire.

Fill in the result column after each run: date and pass or fail.

## Source rules

| # | Rule | Test | Expected | Result |
|---|---|---|---|---|
| 1 | Built-in tools: targeted | `sc.exe stop <LabSvc>` | Fires | |
| 2 | Built-in tools: targeted | `wmic service where name='<LabSvc>' call StopService` | Fires (gap fixed in v4) | |
| 3 | Built-in tools: targeted | `taskkill -f -im <LabSvc>.exe` | Fires (gap fixed in v4) | |
| 4 | Built-in tools: other target | `net stop spooler` | Building block alert only | |
| 5 | PowerShell: high-value | `Stop-Service <LabSvc>` | Building block alert | |
| 6 | PowerShell: other target | `Stop-Service Spooler` | Building block alert | |
| 7 | Targeted service disabled | `sc.exe config <LabSvc> start= disabled` from Automatic | Fires | |
| 8 | Targeted service disabled | Set `<LabSvc>` to Manual, then Disabled | Second command fires (gap fixed in v4; covers VSS) | |
| 9 | Targeted service disabled | `sc.exe config <LabSvc> start= demand` from Automatic | Fires (demotion to Manual) | |
| 9b | Targeted service disabled | Restore a disabled `<LabSvc>` to Manual | Does not fire | |
| 10 | Mass disable or kill | Disable or force-kill 6 lab services within a minute | Fires once per host | |
| 11 | Mass disable or kill | Disable 2 lab services | Does not fire | |
| 12 | Direct registry write | `reg add HKLM\System\CurrentControlSet\Services\<LabSvc> /v Start /t REG_DWORD /d 4 /f` | Fires | |
| 13 | Direct registry write | `sc.exe config <LabSvc> start= disabled` | Does not fire (written by services.exe) | |
| 14 | Shadow copy deletion | Atomic Red Team T1490 tests | Fires | |

## Correlation rules

| # | Rule | Test | Expected | Result |
|---|---|---|---|---|
| 15 | Unlisted stop with targeted disable | Disable `<LabSvc>`, then `net stop spooler` | Fires | |
| 16 | Unlisted stop with targeted disable | `net stop spooler`, then disable `<LabSvc>` | Fires (the reversed order from mentor review) | |
| 17 | Unlisted stop with targeted disable | Only one of the two actions | Does not fire | |
| 18 | Unlisted stop with targeted disable | The two actions 20 minutes apart | Does not fire | |
| 19 | Multiple signals on host | Disable `<LabSvc>` and run the mass test | Fires | |
| 20 | Multiple signals on host | One `sc.exe config <LabSvc> start= disabled` | **Currently fires; should not.** See known-gaps.md | |

## Benign baseline

Before enabling any rule, preview it over the last 24 hours of normal VM activity. Hits in that window are the rule's benign baseline and should be explained or tuned out before testing attacks.

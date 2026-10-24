# Test results

Two validation methods: handcrafted lab tests against fake services, and Atomic
Red Team for independent technique execution. Atomic matters because the tests
were written by someone else, so a rule firing on an Atomic test is evidence the
rule works against the technique, not just against the author's idea of it.

## Lab setup for testing

Six do-nothing Windows services were compiled and registered under names drawn
from Qilin's published kill list, so the rules could be exercised without real
backup, database, or Exchange software present:

```
VeeamTransportSvc, BackupExecJobEngine, SQLLabSvc, MSExchangeLab, GxVss, memtas
```

Distinct display names let each 7040/7034 event be traced to the service that
produced it, which is how the `param1`/`param3`/`param4` field layout was
confirmed.

## Manual tests

| Test | Method | Expected | Result |
|---|---|---|---|
| API-path disable | `Stop-Service` + `Set-Service -StartupType Disabled` on all six | Rules 1 and 2 fire; Rule 3 silent (no process spawned) | Pass |
| Field confirmation | Inspect 7040 in Discover | `param3` = new state, `param4` = service key name, `winlog.user.name` = actor | Confirmed |
| Reset does not fire | Re-enable services (`param3` = `auto start`) | Rule 2 silent (matches only changes *to* disabled) | Pass |
| Registry bypass | Direct `Start` = 4 write via `reg.exe` and PowerShell | Registry rule fires; Rules 1 and 2 silent (no 7040) | Pass — bypass confirmed real and closed |
| PowerShell path | `Stop-Service` / `Set-Service` | 4104 rules fire; Rule 3 silent (no process spawned) | Pass |

The registry and PowerShell results are the important ones: they prove the two
bypasses the extra rules exist to close are real. A direct registry write
produces no 7040, and a PowerShell cmdlet spawns no process, so without the
registry and 4104 rules those paths would be invisible.

## Atomic Red Team: T1489 (Service Stop)

| Test | What it ran | Expected | Result |
|---|---|---|---|
| T1489-1 (default) | `sc.exe stop` on Spooler | 3b (building block) | Pass |
| T1489-1 (`-InputArgs` VeeamTransportSvc) | `sc.exe stop` on a backup service | 3a (High) | Pass — `sc.exe`, parent `cmd.exe`, user `vboxuser` |
| T1489-2 | `net.exe stop` | 3b, twice (`net.exe` and `net1.exe`) | Pass |
| T1489-3 | `taskkill /f /im LabSvc.exe` | Rule 1 at threshold | **Boundary pass** — only 4 services were still running (earlier tests had stopped two), below Rule 1's threshold of 5, so it correctly stayed silent |
| T1489-9 | `iisreset /stop` | n/a | Skipped — IIS not installed; out of scope, `iisreset` not a Qilin tool |

The T1489-3 boundary result is worth keeping: Rule 1 is a 5-service threshold,
and killing 4 correctly did not trip it. It also surfaced a real tuning
question (below).

## Atomic Red Team: T1685 (Disable or Modify Tools)

| Test | What it ran | Result |
|---|---|---|
| T1685-18 (default) | tool against Defender | 3b (Defender not on keyword list) |
| T1685-18 (`-InputArgs` memtas) | tool against a listed service | 3a + Rule 2 + correlation (Critical) |
| T1685-24 | `Remove-Service` via PowerShell against a throwaway service | 4104a |

Default T1685 tests target Windows Defender, which is **not** on the keyword
list, so they land in 3b. This is the T1562.001 (AV/EDR killing) gap: Defender
belongs to a separate technique that needs its own rule, which is why it isn't
folded into the service-stop set.

## Atomic Red Team: T1490 (Inhibit System Recovery)

Run against the Shadow copy deletion rule's six branches. **Snapshot first:
these tests delete real shadow copies.**

| Test | Tool | Expected branch | Result |
|---|---|---|---|
| T1490-1 | `vssadmin delete shadows` | vssadmin | Pass |
| T1490-2 | `wmic shadowcopy delete` | wmic | Pass |
| T1490-3 | `wbadmin delete catalog` | wbadmin | Pass |
| T1490-4 | `bcdedit` recovery | bcdedit | Pass |
| T1490-5 | PowerShell `Win32_ShadowCopy` | PowerShell | Pass |
| T1490-7 | `wbadmin delete systemstatebackup` | wbadmin | Pass |
| T1490-10 | `vssadmin resize shadowstorage` | vssadmin (resize) | Pass — the evasion branch |
| T1490-13 | `diskshadow delete` | diskshadow | Pass |
| T1490-6 | `del` on backup files | none (negative test) | Correctly silent |
| T1490-11 | modify VSS permissions | none (negative test) | Correctly silent |

The resize (T1490-10) and diskshadow (T1490-13) branches were added **after**
reading the full Atomic T1490 test list, which revealed them as ways around a
delete-only rule. Reading the test library before finalizing the query, not
after, is what caught them. Tests 6 and 11 firing nothing is a pass, not a gap:
they confirm the rule is not over-broad.

## Issue found and resolved during testing: rule overlap

The most useful finding. Early correlation tests produced a **false Critical**:
an Atomic `sc.exe` test tripped both the original broad Rule 3 (still live,
Medium) and its replacement 3b (Low). Two different tagged rule names on one
host caused the correlation rule to count 2 and escalate to Critical, from a
single routine command.

**Lesson:** source rules feeding a count-based correlation rule must be mutually
exclusive. Correlation amplifies overlap errors. Deduplicating by tag would have
masked the bug rather than fixing it. The resolution was to retire the broad
rule so 3a and 3b split every match with no overlap.

This is a better portfolio artifact than a page of green checkmarks, because
finding and explaining the overlap demonstrates more than a rule set that
happened to pass.

## Boundary findings and open tuning questions

- **Rule 1 threshold vs small environments.** A small server running only 3–4 of
  Qilin's targets would never trip Rule 1's threshold of 5. Lowering to 3–4
  catches small environments at the cost of more noise from crashes and updates.
  An open trade-off, to decide after benign baseline data.
- **Registry writes need a reboot or a separate stop.** A direct `Start` = 4
  write is not applied by the running SCM until the service restarts or the host
  reboots. A registry-only disable must be paired with a kill or reboot to bite
  immediately; the investigation guide prompts checking for that.
- **7036 not logged on this Windows 10 build.** Polite SCM stops with no disable
  or kill leave no System log trace. Accepted; may differ on Windows Server.
- **Test-tooling noise.** Running Atomic and importing its module generate
  PowerShell script blocks, some of which can surface as 4104b building blocks.
  A lab exception for script text containing `AtomicRedTeam` keeps the test
  harness from feeding the correlation rule.

## Verified during cleanup

- **PowerShell keyword matching.** 4104a fires on a real
  `Set-Service ... -StartupType Disabled` and does **not** fire on a benign line
  containing the keywords as prose ("please set the sql service to backup
  mode"). Matching on the tokenized text field behaves correctly.
- **Composition rule (7) fires.** Confirmed via rule preview that the sequence
  (Rule 2 alert, then 3b alert, same host) matches when both source alerts
  exist in the index.

## Remaining test work

- [ ] Re-run T1489-3 with all 6 services running to confirm Rule 1 fires at the
      threshold (the earlier run killed only 4, correctly below threshold).
- [ ] Benign baseline for every rule: single service stop, Windows Update,
      reboot. A Windows Update did run during testing (build 19045.3803 →
      19045.6466); confirm whether anything fired.

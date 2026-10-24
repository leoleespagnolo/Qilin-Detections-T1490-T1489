# Coverage map: four paths to stop a service

Every service-stop rule in this set exists to close one path by which a service
can be stopped or disabled. This doc explains each path, what it leaves in the
logs, and why the matching rule is built the way it is.

The organizing idea: **how** a service is stopped determines **what** you can
see. The Qilin encryptor is a compiled binary that calls the Windows Service
Control Manager (SCM) API directly, so it never spawns `net.exe` or `sc.exe`,
and command-line rules see nothing from it. But the human operator running the
intrusion, and Qilin's own helper commands, use tools that do leave a trace.
Covering the behavior means covering every path, not just the convenient one.

## Path 1: the Service Control Manager

**Who uses it:** the Qilin encryptor itself, and anything that stops a service
the "normal" way.

**What it leaves:** System log events from the SCM.

- **7034 / 7031** — a service's process terminated unexpectedly (a kill).
- **7040** — a service's start type changed. `param3` is the new type
  (`disabled`, `demand start`); `param4` is the service key name;
  `winlog.user.name` is the account.
- **7036** — a service entered the running or stopped state.
  **Not logged on the tested Windows 10 build**, so polite stops with no
  disable and no kill are invisible here.

**Rules:**

- **Rule 1 (mass disable or kill)** counts distinct services going down per
  host via 7034/7031/7040, with no dependence on a name list. This is the
  backstop: a custom Qilin build with an unknown kill list still trips it.
- **Rule 2 (targeted disable)** fires when a *listed* service is set to
  Disabled or Manual. Disabling a backup or database service is rare and
  high-fidelity, and this is the only SCM-based rule that names the actor.

## Path 2: built-in command-line tools

**Who uses it:** the human operator during hands-on activity, and Qilin's own
VSS sequence (`wmic ... ChangeStartMode`).

**What it leaves:** Sysmon Event 1 (process creation), with the full command
line and the launching parent.

**Tools matched:** `net` / `net1` (stop), `sc` (stop, config), `wmic`
(ChangeStartMode, StopService), `taskkill` (/f).

**Rules, split by target to control noise:**

- **3a (high-value)** fires High when the command targets a listed service.
- **3b (other target)** is the same logic with the target list negated, kept as
  a **building block**: recorded, hidden from the queue, fed to the correlation
  and composition rules.

Matching is on `process.pe.original_file_name` (the name in the binary's PE
header), so renaming `sc.exe` does not evade.

## Path 3: PowerShell

**Who uses it:** operators and scripts using `Stop-Service`, `Set-Service`, or
the CIM `ChangeStartMode` / `StopService` methods.

**Why it needs its own rule:** these run *inside* the PowerShell process and
spawn no new process, so Path 2's Sysmon Event 1 rules are blind to them.
Script block logging (Event 4104) records the code that ran.

**Rules:** same high-value / building-block split as Path 2 (4104a, 4104b).
Written in KQL because the script-block field is `text`-mapped.

## Path 4: direct registry write

**Who uses it:** an operator or malware that disables a service without touching
the SCM.

**Why it matters:** a service's start type is just a registry value,
`HKLM\System\CurrentControlSet\Services\<name>\Start`, where 4 = Disabled,
3 = Manual. Writing it directly produces **no 7040**, so Paths 1 and 2 are
blind. This is a genuine bypass of the two strongest SCM-based rules.

**What it leaves:** Sysmon Event 13 (registry value set).

**Rule:** the registry rule fires on `Start` = 4 for any service, or 3 for a
listed service, and excludes writes by `services.exe` (which is the SCM making
the same change the normal way).

**Caveat:** a registry write does not take effect until the service restarts or
the host reboots, so the service may still be running when the alert fires. The
change still bit if it was paired with a forced stop or a kill.

## The layers on top

### Rule 1 as backstop

Independent of any list, so it catches the one thing the list-based rules
cannot: a Qilin build whose kill list is entirely different from the published
one. Its weakness is that SCM events carry no actor, so it cannot say who.

### Correlation rule (order-agnostic)

Counts distinct `Qilin-service-stop`-tagged rules per host and goes Critical at
two or more. Turns several individually-weak signals into one strong one. It
does not care about order, which makes it robust but imprecise.

### Composition rule (order-aware)

Fires when a targeted disable (Rule 2) is followed by an *unlisted* service stop
(3b) on the same host. The unlisted stop is noise alone, but after a confirmed
targeted disable it likely belongs to this victim's custom kill list. Order is
the signal. This is precise but brittle: miss or reorder a step and it stays
silent.

The correlation and composition rules cover each other. Count catches the messy
real-world cases order misses; order gives a near-zero-false-positive alert that
count cannot.

## Why the tag matters

Source rules (1, 2, 3a, 3b, 4104a, 4104b, registry) carry `Qilin-service-stop`.
The correlation and composition rules do **not**, because they consume that tag;
tagging them would make them count their own output and risk self-reinforcing
escalation. Inputs get the tag, outputs do not.

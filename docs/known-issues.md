# Known issues and fixes

Tracked openly because a detection's blind spots are part of the detection.
The first section is issues found and fixed during development. The second is
what remains open, which is tuning and baseline work, not bugs.

## Resolved during development

These were caught during testing and the export review, and fixed.

- **Rule overlap caused a false Critical.** An early build left the original
  broad command-line rule live alongside its replacement (3b). A single
  `sc.exe` command matched both, and the correlation rule counted two distinct
  rule names and escalated to Critical from one routine action. Resolved by
  retiring the broad rule so 3a and 3b split every match with no overlap.
  **Lesson:** source rules feeding a count-based correlation rule must be
  mutually exclusive; correlation amplifies overlap.

- **PowerShell rules: keyword matching verified.** The script-block field is
  `text`-mapped and tokenizes, which raised a concern that `Set-Service` could
  match as the loose tokens `set` + `service` in unrelated prose. Tested: a real
  `Set-Service ... -StartupType Disabled` fires 4104a, and a benign line
  containing the words as prose ("please set the sql service to backup mode")
  does **not**. Matching is correct; no query change needed.

- **Composition rule: verified firing.** Rule 7 chains two alerts on the alerts
  index (Rule 2 then 3b, in order). Confirmed via rule preview that the sequence
  matches when both source alerts exist. The rule-name references in both steps
  match the live rule names exactly.

- **Rule 3a name cleaned up.** Removed a trailing space and the older wordier
  phrasing; now `Service tampering with built-in tools: targeted services`.

- **Shadow copy investigation guide moved to the correct field.** It was stored
  in `setup` (data-source prerequisites) and is now in `note` (investigation
  guide), so it renders under the right heading.

## Open items

These are tuning and baseline questions, to resolve with more data, not bugs.

- **No benign baseline.** The lab has no production traffic, so the
  false-positive examples in each rule are expected-noise reasoning, not a
  measured rate. The real rate comes from running against production and tuning.
  A Windows Update ran during testing (build 19045.3803 -> 19045.6456); confirm
  whether any rule fired during it.

- **Rule 1 threshold vs small environments.** A small server running only 3-4 of
  Qilin's targets would never trip Rule 1's threshold of 5. Lowering to 3-4
  catches small environments at the cost of more noise from crashes and updates.
  An open trade-off, to decide after baseline data.

- **Confirm Rule 1 fires at the threshold.** The T1489-3 Atomic run killed only
  4 services (two were already stopped by earlier tests), correctly below the
  threshold. Re-run with all six running to confirm the positive case.

- **Composition rule latency, for production.** Rule 7 reads the alerts index,
  so it depends on both source rules writing their alerts inside the window. At
  a 30-minute interval with up to 5 minutes of ingestion delay, it works in the
  lab but could drop chains under heavier production timing. If false negatives
  mattered, widen `maxspan` past the sum of ingestion + interval, or rebuild the
  two steps on raw events and accept duplicating 3b's logic. This is a tuning
  trade-off, not a defect.

- **vssadmin resize branch argument form.** Rule 6's vssadmin branch requires
  one of `delete`/`resize` and one of `shadows`/`shadowstorage` in
  `process.args`. Confirmed against Atomic T1490-10. If a future variant passes
  size only as `/for=` and `/maxsize=` without a bare `shadowstorage` arg, the
  match would need widening.

## Accepted gaps (by design)

- **Event 7036 not logged on the tested Windows 10 build.** A polite SCM stop
  with no disable and no kill leaves no System log trace, so it is invisible to
  Rule 1. The command-line and PowerShell rules cover operator-driven stops.
  May differ on Windows Server.

- **Registry rule has no Atomic coverage.** No Atomic test writes a service
  `Start` value directly, so this rule's only validation is manual.

- **AV/EDR killing is a separate technique.** Default T1685 tests target Windows
  Defender, which is not on the keyword list, so they land in 3b. Defender
  belongs to T1562.001, which needs its own rule rather than being folded into
  the service-stop set.

- **Registry writes need a reboot or a separate stop.** A direct `Start` = 4
  write is not applied by the running SCM until the service restarts or the host
  reboots, so the service may still be running when the alert fires. The
  investigation guide prompts checking for that.

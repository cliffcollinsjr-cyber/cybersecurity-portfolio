# ADS: PowerShell Launched With Encoded Command Switch

`[DEMO]` lab detection. Rule: [`proc_creation_win_powershell_encoded_command.yml`](./proc_creation_win_powershell_encoded_command.yml)
(Sigma id `bb2386f8-201e-4542-9f98-16d53b45f2e8`). Defender twin: [`../detections/defender_encoded_powershell.yml`](../detections/defender_encoded_powershell.yml) (`DET-DEFENDER-DEMO-001`, same regex). Supersedes `DET-SPLUNK-DEMO-001`.

## Goal
Detect PowerShell started with an encoded command (`-EncodedCommand` and every shorthand the
host accepts), a common way to hide script content from casual command-line review and
to sidestep quoting problems when a dropper, macro, or remote tool launches PowerShell.

## Categorization
- MITRE ATT&CK: Execution / T1059.001 PowerShell; Stealth (formerly Defense Evasion) /
  T1027 Obfuscated Files or Information, T1027.010 Command Obfuscation.

## Strategy Abstract
Process-creation telemetry (Sysmon EventID 1 → Splunk via the sysmon pipeline; Defender
`DeviceProcessEvents`). Fire when **both** hold:
1. The process is PowerShell: `Image` ends with `\powershell.exe` / `\pwsh.exe`, **or**
   `OriginalFileName` is `PowerShell.EXE` / `pwsh.dll`. The second check catches renamed copies.
2. `CommandLine` matches one regex: whitespace (or start), a switch introducer
   (`-`, `--`, `/`, en dash, em dash, horizontal bar), an unambiguous prefix of
   `encodedcommand` (`e`, `en`, `enc` ... `encodedcommand`) or the `ec` alias, whitespace,
   then 16 or more Base64 characters, optionally quoted.

## Technical Context
- The PowerShell host matches switches case-insensitively by unambiguous prefix:
  `MatchSwitch(switchKey, "encodedcommand", "e") || MatchSwitch(switchKey, "ec", "e")`.
  `/` and the Unicode dashes (`CharExtensions.IsDash`) are accepted, and pwsh 7 also takes a
  doubled dash (`--`). Source: PowerShell/PowerShell
  `CommandLineParameterParser.cs` (pwsh 7). Windows PowerShell 5.1 source is not public. We
  assume it behaves the same apart from `--`, which only pwsh 7 is documented to accept; the
  rule matches `--` for both, at negligible cost.
- Near misses the regex must skip: `-ExecutionPolicy` (smallest prefix `ex`) and `-ep`;
  `-EncodedArguments` (`encodeda`, `ea`); cmdlet parameters such as `-Encoding`; and paths
  that contain `-enc` (the regex needs whitespace before the switch and whitespace after it).
- The argument is Base64 of UTF-16LE script text. To triage, decode it, for example with
  `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64))`.
- In Splunk the conversion is `EventID=1 Image IN (...) OR OriginalFileName IN (...) | regex CommandLine="..."`.
  SPL gives `OR` higher precedence than implicit `AND`, so the base search means
  `EventID=1 AND (Image OR OriginalFileName)`. Prepend your index/source. Snapshot:
  [`expected/proc_creation_win_powershell_encoded_command.splunk_sysmon.spl`](./expected/proc_creation_win_powershell_encoded_command.splunk_sysmon.spl).

## Blind Spots and Assumptions
- Assumes full command lines are collected (Sysmon EID 1, or 4688 with command-line auditing).
  4688 has no `OriginalFileName`, so renamed binaries are only caught with Sysmon/MDE.
- **Whitespace inside the Base64 argument.** .NET `Convert.FromBase64String` ignores embedded
  whitespace (documented behaviour; not lab-verified here). A quoted argument split into
  chunks shorter than 16 characters (`-e "UwB0AGEA cgB0AC0A ..."`) would therefore evade the
  `{16,}` run. Mitigation: run a lower-severity hunt for the switch token alone
  (regex without the argument part).
- Encoded payloads that are not delivered through the switch, such as
  `-Command "iex([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('...')))"`.
- Script content passed through stdin (`... | powershell -`), environment variables
  (`powershell -c "iex $env:X"`), files, the registry, or download cradles.
- PowerShell without powershell.exe/pwsh.exe: `System.Management.Automation` hosted in another
  process (custom runspaces, PowerShdll-style DLLs, MSBuild inline tasks, InstallUtil) and
  remoting (`wsmprovhost.exe`). Cover these with Script Block Logging (4104) and
  module-load (Sysmon EID 7) detections.
- A copied binary whose PE version info has been edited, so both `Image` and
  `OriginalFileName` are wrong.
- Colon syntax (`-e:<b64>`) is not matched. We have not verified whether the host accepts it.
- Unicode dashes are matched as alternations, not a character class, so the regex stays
  correct when a PCRE engine runs without UTF mode.

## False Positives
- Management and deployment agents (SCCM/Intune, RMM, some installers) that launch encoded
  PowerShell. Allowlist by `ParentImage` + signer/hash + host group, never by command line alone.
- Script text after `-Command` that uses a parameter abbreviated to `-e`/`-en` with a 16+
  character alphanumeric value (for example `Out-File -en BigEndianUnicode`). We consider this rare.

## Validation
- `bash scripts/test_dac.sh`, which runs in CI through `make test-python`, does the following:
  - parses the rule with pySigma and runs the default `sigma check` validators;
  - converts it with the Splunk backend + sysmon pipeline and compares the result to the snapshot;
  - evaluates the Sigma logic, both raw and post-pipeline (`src/sigma_eval.py`), against all
    fixtures in [`../fixtures/sample_events.json`](../fixtures/sample_events.json);
  - evaluates the generated SPL with a narrow interpreter (`src/spl_eval.py`, not Splunk);
  - checks that the Defender KQL regex is identical to the Sigma regex and evaluates its predicates.
- Fixtures cover 11 malicious variants (`-e`, `-ec`, `-en`, `/enc`, `-EncodedC`, en dash,
  `--encodedcommand`, mixed case, quoted argument, renamed powershell.exe, renamed pwsh) and
  9 benign near misses.
- Lab reproduction (safe): `powershell.exe -e RwBlAHQALQBEAGEAdABlAA==` (decodes to `Get-Date`).
  This has not been run against a live Splunk or Defender tenant.

## Priority
High. Encoded launches are uncommon on most endpoints. Escalate to critical when the parent is
an Office app, script host (`wscript`, `cscript`, `mshta`), browser, or a renamed binary is involved.

## Response
1. Decode the argument and review the script content (download cradles, AMSI bypass, credential access).
2. Review the process tree (`ParentImage`, children), user, host, and the network and file activity
   that followed. Pull 4104 script-block logs for the same time window.
3. If it is malicious, isolate the host (MDE), collect artefacts, and block the indicators.
   If it is benign automation, add a narrow allowlist entry (parent + signer + host scope) and record why.

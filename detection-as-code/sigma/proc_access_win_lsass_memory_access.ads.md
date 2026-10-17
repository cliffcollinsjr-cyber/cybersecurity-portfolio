# ADS: LSASS Process Memory Access With Read Rights

`[DEMO]` lab detection. Rule: [`proc_access_win_lsass_memory_access.yml`](./proc_access_win_lsass_memory_access.yml)
(Sigma id `d76f8bfa-378b-4735-8d64-6b08a570d754`). Defender twin:
[`../../edr-microsoft-defender/kql/rare_lsass_access.kql`](../../edr-microsoft-defender/kql/rare_lsass_access.kql) (`DET-DEFENDER-LSASS-001`).

## Goal
Detect a process opening a handle to `lsass.exe` with rights that let it read LSASS memory,
the first step of most credential dumps (Mimikatz `sekurlsa`, MiniDump-based tools).

## Categorization
MITRE ATT&CK: Credential Access (TA0006) / T1003.001 OS Credential Dumping: LSASS Memory.
`sigma check` validated the tags against the ATT&CK data bundled with pySigma 1.5.1 (v20.0).

## Strategy Abstract
Sysmon EventID 10 (ProcessAccess) → Splunk via the sysmon pipeline; Defender `DeviceEvents`
`OpenProcessApiCall`. Fire when all hold:
1. `TargetImage` ends with `\lsass.exe`.
2. `GrantedAccess` has `PROCESS_VM_READ` (0x10) set, or is exactly `PROCESS_DUP_HANDLE` (0x40).
   Sysmon writes the mask as hex, so VM_READ is set when the second-lowest hex digit is odd:
   regex `(?i)^0x[0-9a-f]*[13579bdf][0-9a-f]$`. KQL uses `binary_and(DesiredAccess, 0x10)`.
3. The caller is not on a short allowlist matched by **full path**: csrss, wininit, lsm and
   WmiPrvSE in `C:\Windows\System32`, svchost only with `0x1410`, MsMpEng under
   `C:\ProgramData\Microsoft\Windows Defender\Platform\`, and vmtoolsd in its install folder.
   Exception: a call trace through `\dbghelp.dll`, `\dbgcore.dll` or `UNKNOWN(` (code in
   unbacked memory) fires even for allowlisted paths (Sigma only; MDE has no call stack).

## Technical Context
- Access rights (Microsoft "Process Security and Access Rights"): `PROCESS_VM_READ` 0x0010,
  `PROCESS_DUP_HANDLE` 0x0040, `PROCESS_QUERY_LIMITED_INFORMATION` 0x1000,
  `PROCESS_ALL_ACCESS` = 0x1F0000 | 0xFFFF (Sysmon shows 0x1fffff).
- Why a bitmask instead of a list: SigmaHQ `proc_access_win_lsass_susp_access_flag.yml` already
  encodes the same idea as `GrantedAccess|endswith` lists ('30','50',...,'FA') and leaves the
  '10' ending to a sibling rule. Its comments mark 0x1010/0x1410 as noisy and keep 0x1438,
  0x143a, 0x1f0fff, 0x1f1fff, 0x1f3fff and 0x40. SigmaHQ `proc_access_win_lsass_memdump.yml`
  uses 0x1038/0x1438/0x143a/0x1fffff with dbghelp/dbgcore call traces. Mimikatz `sekurlsa`
  opens with 0x1010 (VM_READ | QUERY_LIMITED_INFORMATION), so this rule keeps 0x1010 and
  depends on the path allowlist for noise control.
- Comsvcs: `rundll32 comsvcs.dll,MiniDump <pid> <file> full` calls MiniDumpWriteDump
  (dbgcore) and shows up as a VM_READ-bearing handle opened by `rundll32.exe`, which is not on
  the allowlist (SigmaHQ `proc_access_win_lsass_dump_comsvcs_dll.yml`).
- Defender: according to the community schema references I checked (detection.wiki,
  xdrinternals.com), `DeviceEvents` `OpenProcessApiCall` puts the target in `FileName` and the
  integer mask in `AdditionalFields.DesiredAccess`. The Microsoft Learn DeviceEvents page lists
  `FileName`, `InitiatingProcessFolderPath` and `AdditionalFields`. It does not list
  ActionType values.

## Blind Spots and Assumptions
- Sysmon must log ProcessAccess with lsass.exe as a target. Many configs exclude EID 10 or
  filter it heavily because of volume.
- **Handle duplication / handle stealing:** a tool that duplicates a handle another process
  already holds (for example from an allowlisted AV or from lsass's own children) gets no new
  OpenProcess on lsass. Only the 0x40 open to the *source* of the handle is visible, and only
  when that source is lsass.
- **Forked/cloned lsass (nanodump `--fork`, PssCaptureSnapshot):** the read can target a
  snapshot or clone, not lsass. Some variants still open lsass with
  `PROCESS_CREATE_PROCESS` (0x80) only, which has no VM_READ bit and is not matched.
- **SilentProcessExit / WerFault dumps:** WerFault, started via registry, writes the dump.
  WerFault is not allowlisted here, so its open would match, but the trigger itself (registry
  change) is better caught by a registry rule.
- **Direct syscalls:** Sysmon EID 10 comes from the kernel's ObRegisterCallbacks, so
  `NtOpenProcess` by syscall is still logged. The CallTrace then often shows `UNKNOWN(`.
  This rule assumes kernel callbacks were not tampered with.
- **Driver-based reads / PPL bypass via vulnerable drivers:** kernel reads need no user-mode
  handle and are not seen.
- **Offline credential theft:** SAM/SECURITY hive copies, NTDS.dit (T1003.002/.003),
  hibernation or crash-dump files, and VM snapshot memory are out of scope.
- **Allowlisted paths:** an attacker who can write to `C:\Windows\System32` or the Defender
  platform folder, or inject into an allowlisted process without leaving a suspicious call
  trace, is not detected. Paths are matched exactly; Sysmon reports canonical image paths.
- LSASS running as PPL (RunAsPPL) blocks VM_READ opens from non-protected processes. The
  open may still be logged, which this rule treats as a true positive attempt.

## False Positives
EDR/AV, backup, monitoring and vulnerability-scanning agents not on the allowlist, plus
authorized admin/IR dumps (Task Manager "Create dump file", procdump). Task Manager is
deliberately **not** allowlisted because its dump feature is a known LSASS dump method.
Allowlist further agents by exact path, ideally with signer or hash.

## Validation
- Offline: `bash scripts/test_dac.sh` runs the rule on 37 fixtures (17 EID 10) with the
  Sigma evaluator, the generated SPL interpreter and the KQL hand translation.
- Lab (authorized, isolated VM only): `procdump64.exe -accepteula -ma lsass.exe out.dmp`, or
  `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass pid> C:\Temp\l.dmp full`
  from an elevated shell. Expect EID 10 with `GrantedAccess` 0x1fffff (or similar) and
  dbgcore/dbghelp in CallTrace.

## Priority
High. A non-allowlisted read handle on LSASS rarely has a benign explanation outside
security tooling. EVT-LSASS-005-style events (call trace from unbacked memory) are critical.

## Response
1. Identify the source image, its hash and signer, the user, and the parent process tree.
2. Look for dump files (`*.dmp`) written around the event time, and for outbound transfer.
3. If it is not authorized, isolate the host, then reset credentials for accounts that logged
   on to it (including service accounts and cached domain admins) and krbtgt if domain
   credentials are at risk.
4. If it is a legitimate agent, add an exact-path allowlist entry to both the Sigma rule and
   the KQL. The tests enforce parity between the two.

## Depth: variants covered vs evasions
| Variant | Covered? | Fixture |
|---|---|---|
| Direct OpenProcess with VM_READ (Mimikatz 0x1010) | Yes | EVT-LSASS-001 |
| procdump -ma (0x1fffff, dbghelp) | Yes | EVT-LSASS-002 |
| rundll32 comsvcs.dll MiniDump | Yes | EVT-LSASS-003 |
| Renamed tool in %TEMP% | Yes (no reliance on name) | EVT-LSASS-004 |
| Impostor allowlisted filename in a wrong path | Yes (path-scoped filters) | EVT-LSASS-008 |
| Code injected into an allowlisted process (UNKNOWN call trace) | Sigma yes, KQL no | EVT-LSASS-005 |
| PROCESS_DUP_HANDLE open (handle-dup prep) | Yes | EVT-LSASS-006 |
| Handle stolen from another process | No | — |
| nanodump fork / PssCaptureSnapshot with 0x80 only | No | — |
| SilentProcessExit via WerFault | Partial (WerFault open matches; registry trigger out of scope) | — |
| Kernel driver reads | No | — |
| Offline SAM/NTDS/hiberfil | No (other sub-techniques) | — |

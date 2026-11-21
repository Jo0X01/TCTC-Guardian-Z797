# Changelog

All notable public releases of TCTC Guardian Z797 are documented here.

## [1.0.0] - 2026-11-21 — First public release

### Detection and investigation
- Focused coverage for the analysed TCTC / Z797 ClickFix chain rather than general-purpose antivirus scanning.
- Targeted process inventory, read-only process-memory inspection, staging-file checks, persistence review, local network/DNS evidence, and campaign-correlated historical/live Windows telemetry.
- Findings include source evidence, timestamps, process identity, matched indicators, confidence boundaries, coverage limitations, and available response actions.
- Historical event sources are reported as read, disabled, unavailable, pending, or failed; unavailable evidence is not presented as clean.

### Read-only memory inspection
- Uses Windows APIs such as `OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, Toolhelp snapshots, `NtQueryInformationThread`, and `QueryWorkingSetEx` for targeted inspection of the documented process allow-list.
- Reports actual API work counters and distinguishes metadata enumeration from targeted byte reads.
- Does not write to remote process memory, patch code, queue APCs, or inject threads. This is not a full-memory dump or byte-for-byte scan of every process.

### Response and safety
- Revalidates current file identity using SHA-256, size, path, and process identity before exact-sample containment.
- Supports narrowly scoped, confirmation-gated cleanup for verified Z797 files and persistence artifacts, with backups for reversible changes.
- Historical records, DNS cache observations, generic memory anomalies, and unattributed endpoints remain review-only.
- Sysmon defaults to Event 29 detect-only. PE creation is not blocked.

### Safe validation
- Includes an inert `[LAB]` canary workflow that creates a text-only test artifact and a harmless `cmd.exe` `echo` process event.
- The lab does not implement process injection, AMSI tampering, persistence, credential access, C2 traffic, or remote-memory modification.

### User interface and operation
- PySide6 desktop interface with tray support, readable Findings detail, compact Settings, live activity, and local HTML reports.
- Continuous monitoring runs only while the application remains open or minimized to the tray; Guardian is not a Windows service.

### Validation status
- Portable verification in the preparation environment: 252 unit tests passed, Python compilation passed, application self-check passed, and the source archive passed integrity validation.
- Windows integration remains a user-side validation requirement: UAC, WinTrust, Sysmon service/driver installation, native Event Log delivery, live process-memory reads, remediation APIs, Qt rendering/DPI, and Nuitka packaging were not executed in the Linux preparation environment.

### Licensing
**The original TCTC Guardian Z797 project code is not offered under the GNU General Public License or any other open-source license. All rights are reserved.** No permission to copy, modify, sublicense, publish, redistribute, or incorporate the project code into another product is granted by making this repository public. Obtain written permission from the project owner before reusing the original project code.

Licenses belonging to third-party components (for example Python, Qt/PySide6, and watchdog) apply only to those respective components. They do not grant a license to the original TCTC Guardian Z797 code. Microsoft Sysmon is downloaded separately from Microsoft and is not included in this repository.

The repository intentionally uses [`LICENSE-PENDING.md`](LICENSE-PENDING.md) to record that no standard open-source license has been selected. **Do not add a GPL-3.0 `LICENSE` file unless the project owner explicitly changes this decision.** See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for component-specific notices.
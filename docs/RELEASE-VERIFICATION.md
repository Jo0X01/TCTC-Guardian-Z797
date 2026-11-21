# Release verification — v1.0.0

**Release:** First public release
**Application source version:** 1.0.0
**Target:** Windows 11 / Windows Server 2019+ (confirm exact build support using `docs/SYSMON-REQUIRED.md`)
**Package type:** Python source / GitHub package

## Portable source checks

- Python compilation: PASS
- Application self-check: PASS
- Unit tests: 252 / 252 PASS
- Safe lab simulator lifecycle: PASS in an isolated temporary directory
- ZIP integrity and SHA-256: PASS
- Sysmon XML: Event 29 detect-only; no Event 27 `FileBlockExecutable`
- No Windows Defender / MDE telemetry collection in the active Guardian pipeline

## First-release scope

- Sample-specific TCTC/Z797 process, memory, file, persistence, network, and historical/live event investigation.
- Read-only memory collection with API work counters and explicit inspection-depth / coverage-gap states.
- Five historical event source groups with explicit disabled/unavailable/error states.
- Corrected remote-endpoint and persistence enumeration counters in reports.
- Finding evidence details and action-specific, current-target response paths.
- Exact-sample quarantine and reversible persistence/Hosts remediation with revalidation and backups.
- Safe `[LAB]` canary workflow for validating detection and file quarantine without executing malware.
- Sysmon Event 29 detect-only; no PE creation blocking.

## Windows integration not yet verified by the preparation environment

The build environment is Linux. This release has not been tested here against actual Windows UAC, WinVerifyTrust, Sysmon installation/service/driver, native Event Log delivery, live process memory and handle behavior, real remediation, Qt rendering/DPI or Nuitka packaging. Run `WINDOWS-VALIDATION.md` on a disposable Windows 11 / Windows Server 2019+ VM before relying on live response or distributing a binary.

## Licensing

No license has been selected for the project code. All rights are reserved until the owner chooses and adds a standard license. See `LICENSE-PENDING.md` and `THIRD-PARTY-NOTICES.md`.

# Local test results — TCTC Guardian Z797 v1.0.0

Prepared in the non-Windows source preparation environment (Python 3.13 / Linux).

## Current result

- Full suite: **252 / 252 passed** (`python -m unittest discover -s tests -t . -q`).
- Compilation: `python -m compileall -q src tests`.
- Application self-check: `python src/main.py --self-check`.
- Safe lab lifecycle: prepare/status/cleanup passed in an isolated temporary directory.
- Sysmon XML / detect-only policy contract: passed.
- Source ZIP integrity: passed; SHA-256 sidecar generated and checked.

## Coverage represented by the portable suite

- Exact actor-side ProcessAccess attribution and rejection of target-only or incomplete identity matches.
- Historical and live parsing for Sysmon, Security process/persistence, PowerShell 4103/4104, Task Scheduler, and WMI Activity.
- Read-only memory API-path fixtures for OpenProcess, VirtualQueryEx, ReadProcessMemory, PE-header probes, thread/module snapshots, NtQueryInformationThread, QueryWorkingSetEx, and AMSI export inspection.
- Memory inspection-depth states, per-process counters, zero-region coverage-gap handling, and no remote-memory-write behavior.
- Exact-sample cleanup revalidation, quarantine boundaries, persistence/Hosts backups, and rejection of stale or generic targets.
- Safe lab marker, `[LAB]` evidence labelling, process event simulation, and bounded cleanup.

## Platform limitation

The test environment is Linux. Fixtures, mocks and source-contract tests do not validate Windows WinTrust, UAC, DISM, Sysmon driver installation, live Event Log subscriptions, real process-memory reads, process handles, Registry/Task/Service/Firewall remediation, PySide6 GUI rendering/tray integration, or Nuitka packaging. Complete `docs/WINDOWS-VALIDATION.md` on a disposable Windows 11 / Windows Server 2019+ test machine.

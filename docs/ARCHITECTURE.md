# Architecture

- `src/guardian/indicators.py`: sample-specific path and command heuristics testable without Windows.
- `src/guardian/memory.py`: read-only Win32 memory collector. It enumerates virtual-memory regions only for the fixed Z797-relevant targets, checks private executable allocations, inspects PE headers, correlates thread starts, identifies copy-on-write image pages, checks sample-related AMSI stubs and streams region evidence.
- `src/guardian/network_diagnostics.py`: local DNS-cache, Hosts, gateway and socket collection. It never resolves or contacts configured C2 indicators.
- `src/guardian/remediation.py`: explicit response operations with hash verification, quarantine/restore/permanent-delete safeguards, selected Registry/task/service/Hosts backups, verified outbound Firewall block rules with rollback, and evidence-first process containment where supported.
- `src/guardian/reports.py`: local JSON and escaped HTML investigation reports with component credits and coverage limitations.
- `src/guardian/ui.py`: compact PySide6 desktop window, `QSystemTrayIcon`, QThread scan/monitor workers, evidence review, Quarantine recovery, Threat Profile settings and Legal & Credits page. No Tkinter code is used.
- `assets/app-icon.png` / `assets/app-icon.ico`: application mark and Windows icon.
- `src/main.py`: application entry point, mandatory Administrator request on Windows, local rotating log, dependency check and self-check.

## Memory analysis

The collector only requests query/read access to other processes. The allow-list is fixed to `RuntimeBroker.exe`, `explorer.exe`, `chrome.exe`, and `csc.exe` only when the executable image is under the sample-specific `Temp\\Local` path. An imported Threat Profile cannot widen it. `VirtualQueryEx` supplies region metadata; `ReadProcessMemory` reads region headers and streams selected region captures. Thread start addresses are queried with `NtQueryInformationThread`. `QueryWorkingSetEx` is used as a copy-on-write signal, not proof that a page is malicious. The AMSI check reads the two relevant exports from mapped `amsi.dll` and looks for the return stub recovered during analysis.

No target-process memory is written, patched, re-protected or unmapped. A high-confidence finding with a complete evidence capture can be followed by a context-aware whole-process termination action after the selected policy authorizes it. The tool never attempts to disable one arbitrary page inside a live process.

## Threading and monitoring

The GUI thread only updates widgets and handles confirmation prompts. On-demand investigations and periodic monitor cycles run in `QThread` workers. A shared lock prevents overlapping engine runs. Closing the window hides it to the system tray; Exit requests cancellation and waits asynchronously for workers to stop. Periodic monitoring runs only while the app process remains alive; the optional Windows Scheduled Task can launch the app at logon hidden to the tray, but there is no persistent Windows service.

## Threat configuration

Settings store sample-related domains, IPs, URLs/paths, ports, custom scan roots, monitoring preferences and response policies. Local Threat Profiles are JSON and schema-checked; they are not cryptographically signed in this release. Profiles cannot expand the memory allow-list. The custom rule editor from older UI builds has not been carried forward as an executable rule engine; arbitrary user scripts/commands are not executed.

## Deliberate capability gaps

A full module-to-trusted-image integrity engine, historical APC telemetry, a persistent Windows service, complete adapter DNS restoration, signed remote Threat Profile updates, automatic application updates, the complete declarative custom-rule engine and evidence-at-rest encryption are not complete. Event-driven subscriptions receive future records only and depend on provider availability and pre-existing audit/configuration policy. The periodic investigation remains a second line of checking. PowerShell 4103/4104 are Script Block/Module logging telemetry, not a direct AMSI result hook. Thread-pool/API names are matched only if an available telemetry provider contains them; Sysmon is not a universal API-call tracer. File notifications begin after the write starts and do not guarantee pre-execution blocking.

The source and test suite can be exercised in a non-Windows development environment, but the Win32 collector and new PySide6 UI must be validated on actual Windows 10/11 systems. See `WINDOWS-VALIDATION.md`.

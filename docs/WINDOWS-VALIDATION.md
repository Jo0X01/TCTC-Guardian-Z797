# Windows validation checklist — TCTC Guardian Z797 v1.0.0

This checklist is for a disposable Windows 11 test machine. The source package was validated in a non-Windows build environment; this checklist does not imply that Windows runtime, UAC, Sysmon driver installation, event subscriptions, process memory inspection, or Qt rendering have already been tested here.

## 1. First launch and interface

- [ ] Install dependencies and confirm `python -c "import PySide6; print(PySide6.__version__)"` succeeds.
- [ ] Start `Run-TCTC-Guardian.bat` as instructed; verify the elevation prompt and the app's administrator status.
- [ ] Confirm the fixed 1000×700 window, tray icon, Overview, Findings, and the simplified Settings tabs (`Basics`, `Z797 checks`, `Advanced`).
- [ ] Verify the Findings details pane distinguishes a historical record from a current/live sensor result. A live event may have Event ID and Record ID; those fields alone must not make it historical.
- [ ] Select a context-only or historical finding. Confirm the action button reads `No safe cleanup action` and is disabled.
- [ ] Select an eligible current finding. Confirm the button label matches its action type and that a separate confirmation is required.
- [ ] Confirm long evidence values wrap, timestamps and event identifiers are readable, and missing hashes are explained as unavailable for that event type.

## 2. Settings are real controls, not cosmetic switches

- [ ] In `Basics`, change the monitoring interval and notification preference; save, restart, and verify persistence.
- [ ] Enable/disable logon startup; verify the corresponding per-user scheduled task is created or removed.
- [ ] In `Z797 checks`, toggle each stage (processes, memory, persistence, staged files, network, and event logs), save, run an investigation, and verify the corresponding stage is included/excluded in coverage.
- [ ] Confirm memory checks imply the process enumeration needed to identify the fixed sample-relevant targets; disabling memory does not disable all process checks.
- [ ] In `Advanced`, change the event-log record cap and memory evidence settings; verify the new values are passed to the engine and are reflected in coverage/evidence output.
- [ ] Confirm there are no visible settings for arbitrary custom IOCs, arbitrary scan roots, browser-profile scanning, Windows Defender, or generic antivirus behavior.
- [ ] Confirm the fixed built-in Z797 indicator set cannot be widened by editing the settings JSON or importing a third-party profile.

## 3. Exact Z797 scope — no generic antivirus scan

- [ ] Confirm the only default disk staging roots scanned are `%TEMP%\Local` and `%WINDIR%\Temp\Local`; no whole-drive scan occurs.
- [ ] Confirm no browser profile databases, browser history, cookies, Chrome Local State, or unrelated user documents are traversed or parsed.
- [ ] Confirm a generic PowerShell command, encoded PowerShell text without Z797 delivery indicators, generic download command, browser process, or ordinary Temp file does not create a Z797 finding by itself.
- [ ] Confirm campaign-specific script/stager names and exact recovered file hash+size pairs are matched as described in `docs/DETECTION-MAP.md`.
- [ ] Confirm an Event 29 PE-creation event is not treated as a confirmed Z797 artifact from its event ID alone; the actual file must be re-examined and matched by exact identity/size or validated campaign marker.
- [ ] Confirm the app does not contact campaign domains or IP addresses during investigation. Network inspection is local/read-only apart from an explicitly approved, exact-IP Firewall response.

## 4. Historical and live telemetry

- [ ] Verify only relevant channels are queried: Sysmon Operational, Windows Security, PowerShell Operational, Task Scheduler Operational, and WMI Activity Operational.
- [ ] Verify Windows Defender / Microsoft Defender Operational and MDE telemetry are not queried, subscribed to, imported, or rendered as Guardian findings.
- [ ] Confirm historical PowerShell Script Block/Module events 4104/4103 are reviewed only for campaign-specific indicators; an arbitrary script block is not a detection.
- [ ] Confirm broad Security object-access event 4663 and Audit Policy-change event 4719 are not used as generic infection findings.
- [ ] Verify the per-channel record cap is respected and the report shows returned, examined, and truncated counts. A capped or unavailable source must be shown as a coverage limitation, not as clean.
- [ ] Verify live event subscriptions are separate from historical queries. A live event can carry Event ID/Record ID without being labelled historical.
- [ ] Verify ProcessAccess attribution uses the actor/source process identity (Process GUID, image and PID where present) and only write-capable access. A target such as Explorer/RuntimeBroker by itself is not attribution.
- [ ] Verify DNS cache observations are low-confidence context only. An IOC IP in a DNS cache or an unattributed connection must not become a confirmed infection finding or offer cleanup.

## 5. Persistence and file response

Use harmless synthetic values in a disposable VM. Never execute the original malware, extracted payload, or reconstructed shellcode.

- [ ] Place a benign file with a known test Z797 marker in a disposable allowed staging root. Confirm the file finding displays its path, size, computed hash, matched marker, and exact rationale.
- [ ] Modify the file after the finding is created. Confirm cleanup re-hashes and rechecks size/identity, then refuses the stale action.
- [ ] Confirm a filename-only match, generic `Temp\Local` path, arbitrary executable, or unknown hash cannot be quarantined automatically.
- [ ] Confirm exact known-artifact auto-containment only occurs with the exact SHA-256 + exact byte size + allowed staging path, and the live process is pinned/revalidated before termination.
- [ ] Create a Run/RunOnce test value containing an exact synthetic campaign marker. Confirm the finding shows the value name and command; the action backs up and removes only that value after re-reading it.
- [ ] Create a scheduled-task test entry containing an exact synthetic campaign marker. Confirm the action backs up its definition, re-reads the action, and disables only that task.
- [ ] Create a test service pointing to an exact synthetic campaign marker. Confirm the action backs up its configuration, revalidates its ImagePath, and disables/stops only that service.
- [ ] Add an exact synthetic C2 mapping to a disposable Hosts file. Confirm the action backs up the file and removes only the matching line.
- [ ] Confirm RunMRU, DNS cache, historical event records, and generic telemetry remain evidence-only; Guardian must not offer actions that clear those histories.
- [ ] Confirm each reversible system modification creates a backup and logs the action/result. Verify rollback/restore on the disposable machine.

## 6. Memory and process monitoring

- [ ] Confirm live memory inspection is read-only and limited to the fixed sample-relevant process allow-list documented in the UI and `docs/DETECTION-MAP.md`.
- [ ] Confirm `csc.exe` is eligible only under the exact staging path rule, not by process name alone.
- [ ] Confirm generic private executable memory, thread start addresses, copy-on-write pages, or AMSI stub anomalies remain contextual unless the sample-specific indicators and correlation rules are met.
- [ ] Confirm the application does not call `WriteProcessMemory`, `VirtualProtectEx`, remote thread creation, APC injection, or other process-memory write APIs.
- [ ] Confirm no process is terminated solely because of its name, target-process identity, or a historical ProcessAccess record.
- [ ] Confirm unreadable/protected process regions appear as coverage gaps rather than a clean result.

### Memory API work counters

- [ ] In a run with eligible processes, verify the HTML report records selected/opened process counts and non-zero `VirtualQueryEx` call / successful-region counts for each successfully opened target.
- [ ] Verify `ReadProcessMemory` calls and bytes are counted only when the API is actually called; zero targeted reads must be labelled metadata-only rather than implying that bytes were scanned.
- [ ] Verify private executable region PE-header probes, thread enumeration / start queries, image-page working-set checks, module snapshots and AMSI export checks show attempted/success/failure counts where applicable.
- [ ] Verify a target with no regions returned by `VirtualQueryEx`, an inaccessible target, or a failed read creates a visible coverage gap; it must not be reported as a clean memory inspection.
- [ ] Verify the per-process table matches the aggregate counters and the allow-list remains RuntimeBroker, Explorer, Chrome, and `csc.exe` only under the exact Temp\Local staging path.
- [ ] Verify `OpenProcess` uses query/read-only access only. The scanner must not call `WriteProcessMemory`, `VirtualProtectEx`, remote thread creation, or APC queueing APIs.

## 7. Sysmon and Detect-only policy

- [ ] Verify the Python-native bootstrap downloads Sysmon only from the Microsoft Sysinternals distribution endpoint, validates the ZIP, and verifies the Microsoft Authenticode signer before install/use.
- [ ] Confirm setup does not invoke PowerShell for the install path and does not replace an organization-managed Sysmon policy without explicit approval.
- [ ] Confirm the active configuration includes Event 29 `FileExecutableDetected` for PE creation detection and does not include Event 27 `FileBlockExecutable`.
- [ ] Create a harmless executable in the test staging directory; confirm a telemetry event is logged and the file is not blocked.
- [ ] Verify the service, Operational channel, active configuration, and configuration hash marker after setup and after restart.
- [ ] Stop Sysmon or make the Operational channel unavailable; confirm Guardian reports degraded coverage/protection state rather than claiming the device is fully monitored.

## 8. Final response and recovery

- [ ] Verify each actionable finding has a clear action label, target, rationale, confirmation, revalidation, backup/rollback where applicable, and final status.
- [ ] Verify historical/context-only findings are review-only and do not expose a cleanup button.
- [ ] Verify Firewall changes are disabled unless the user approves the exact Z797 IP and the relevant process attribution; only Guardian-owned rules may be rolled back.
- [ ] Confirm a successful targeted scan is described as “no matching evidence found in the inspected scope,” not proof of eradication.
- [ ] Confirm monitoring is in-app and stops after full application exit; this is not a Windows service or an always-on boot driver.

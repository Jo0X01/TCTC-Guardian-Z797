# Implementation status — v1.0.0 (first public release)

## Product boundary

This release is a narrowly scoped detector and response utility for the locally analysed TCTC / Z797 ClickFix chain. It does not attempt to be a general antivirus, import unrelated vendor alerts, or merge sibling ClickFix / LegionLoader / ROMULUS IOCs.

## Implemented stages

| Stage | What is inspected | What can count as a Z797 Finding |
|---|---|---|
| Processes | Current process inventory and image paths | Exact recovered sample SHA-256 + byte-size match executing from an analysed staging root |
| Memory | Read-only inspection of RuntimeBroker, Explorer, Chrome, and staged `csc.exe` | Sample-observed private PE mapping, thread-start, image-identity or AMSI-stub effects; anomaly confidence and limitations are shown, and these findings are not process-kill targets |
| Staging files | `%TEMP%\Local` and `%WINDIR%\Temp\Local` | Exact artifact hash+size, exact delivery filename, or a recovered Z797 URL/domain marker in a supported text/script-like file |
| Persistence | Run / RunOnce, Services, Scheduled Tasks, Startup folders and selected WMI event history | Current command/action contains an exact Z797 indicator or points to a recovered artifact |
| Network | DNS cache, Hosts and active endpoint table | Exact Hosts mapping; DNS cache is Low-confidence context only; active C2 connection is promoted only when its process is an exact recovered payload |
| Event history | Sysmon, Security process/persistence events, PowerShell 4103/4104, Task Scheduler and WMI Activity | Exact Z797 URL/domain/artifact marker or complete actor-side identity correlation, not an event type or target process name alone |
| Verification | Collection status, per-source coverage, limits and errors | Reports unreadable/disabled/overwritten sources as coverage gaps, not a clean result |

Historical event queries are capped at 5,000 selected event records per channel by default; Guardian parses those records for Z797-specific indicators. The query asks for one extra row to detect likely truncation, and report coverage separates returned, inspected and unavailable sources. Windows can only return events that were enabled, retained and accessible.

## Settings behavior

All visible toggles have direct consumers:

- Monitoring enabled / interval / notifications / sign-in startup control the monitor worker, notifications and Windows startup task.
- Process, memory, file, persistence, network and event-history toggles map to ScanEngine stages and live subscriptions where supported.
- Event-history limit controls the per-channel selected-event query cap.
- Memory evidence capture and the private-code, manual-map, thread-start, mapped-image and AMSI indicators are passed to the memory collector.
- Exact-payload automatic containment controls the strict hash+size+path+live-process identity gate.
- Firewall preference controls whether a confirmed exact-payload connection can offer an outbound block rule.

Legacy unused generic scan controls and arbitrary custom roots are not exposed or persisted as active settings.

## Response actions and guardrails

- Files: re-check current path, regular-file status, exact size and SHA-256, and require either an exact recovered artifact or an embedded Z797 marker before quarantine. The path must be one of the two analysed staging roots or an approved Startup folder. Filename-only matches are never enough.
- Processes: stop only an exact recovered payload after verifying SHA-256, size, staging path and a pinned process handle. Do not kill Explorer, RuntimeBroker or Chrome because of a generic memory observation.
- Run / RunOnce: re-read the exact value, verify the Z797 marker, back up data and remove only that value.
- Scheduled task: re-read task XML/action, verify the Z797 marker, back up details and disable only that task.
- Service: re-read exact ImagePath/start mode, back up configuration, disable and request stop only for the matching service.
- Hosts: back up the file and remove only the exact built-in Z797 domain mapping.
- Firewall: offer an outbound rule only for a built-in confirmed address and an exact recovered payload identity, after explicit confirmation.
- DNS cache, RunMRU and old event records are evidence, not cleanup targets. The program does not clear all DNS entries, erase logs or delete unrelated user files.

Automatic containment is restricted to exact recovered files with a matching SHA-256 and byte size, an analysed staging path and a verified live process identity. Other response actions require explicit user confirmation.

## Monitoring and sensor requirements

Sysmon is downloaded from Microsoft at runtime by the Python-native setup, Authenticode-verified and configured with Event 29 detect-only. Guardian does not configure Event 27 PE creation blocking. Continuous monitoring runs only while the application remains open or in the tray; this is not a Windows service. Filesystem notifications cover only the two analysed staging roots and occur after writing starts.

## Not implemented / not guaranteed

- No full-disk scan, kernel driver, universal API hook, guaranteed pre-execution block, or guaranteed APC history reconstruction.
- No automatic cleanup of arbitrary browser data, DNS cache, Windows logs or unknown files.
- No inference of infection from process name, target-process name, Temp path, IP-only network match or generic memory region alone.
- Memory collection is read-only. No remote-memory writing, code patching, APC queueing or injection is performed.
- Unknown dynamic plugin payloads and future C2 task values outside the recovered profile cannot be detected from static indicators alone.

## Validation status

Portable Python tests, fixtures, mocks, compile checks and source self-checks pass in the non-Windows build environment. Real Windows WinTrust, UAC, Sysmon service/driver installation, native Event Log delivery, process memory access, registry/task/service/Firewall cleanup, GUI rendering and DPI behavior still require validation on a disposable Windows 11 / Server 2019+ machine. See `WINDOWS-VALIDATION.md`.

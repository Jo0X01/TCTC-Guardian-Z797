# Real-time monitoring design — TCTC Guardian Z797

## What is implemented in source

The application uses two complementary future-event sensors while its in-app monitor is running:

1. **Windows Event Log push subscriptions** through `EvtSubscribe` for the channels below. Events are queued and parsed on worker threads; callbacks do not perform hashing, remediation, or GUI work.
2. **A targeted filesystem observer** for only `%TEMP%\Local` and `%WINDIR%\Temp\Local`. It hashes new/changed files on a background worker and compares exact SHA-256 plus byte size against the seven locally recovered artifact records.

Subscriptions receive future events only. They do not replay history from before the app started. A five-minute targeted scan remains as a second line of checking and initial-state inventory. The memory inspection remains a periodic read-only snapshot of the fixed target process list, not a real-time hook into every allocation or API call.

## Event sources and dependencies

| Provider / event | Purpose | Required configuration / limitation |
|---|---|---|
| Sysmon 1 | Process image, command line, parent, ProcessGuid and hashes | Mandatory; targeted policy sets `HashAlgorithms` to `SHA256` |
| Sysmon 2 / 26 | Staging file creation-time changes and deletion attempts | Mandatory file-cleanup telemetry, scoped to the two sample staging roots |
| Sysmon 4 / 16 | Sysmon service state and configuration changes | Mandatory sensor-integrity events; stop protection on stop/config change |
| Sysmon 29 | PE file creation detected in the two staging roots | Detect-only; this release does not configure or enable Event 27 blocking |
| Sysmon 3 / 22 | Network connections and DNS queries | NetworkConnect and DNSQuery must be enabled in Sysmon config; Event 3 is often disabled in default configs |
| Sysmon 7 | Image loads from the exact staging tree | ImageLoad must be enabled with path filtering |
| Sysmon 8 / 10 / 25 | Remote thread, process access and process tampering involving the target processes | These event types must be configured; Event 8/10 actor attribution requires exact source ProcessGuid + image + PID join. Event 10 additionally requires write-capable access rights. Direct IOC matches are High; inherited lineage is Medium; target-only or incomplete matches are context-only. |
| Sysmon 11 | File creation/overwrite plus creator PID/Image | Mandatory; FileCreate is limited to the two sample-specific Temp\Local roots |
| Sysmon 12–14 | Registry object/value changes | Config filters to Run / RunOnce paths; the app still requires a campaign marker or already correlated process |
| Security 4688 | Process creation and parent PID | Advanced Audit Policy → Process Creation must be enabled; command-line text requires the separate “Include command line in process creation events” policy |
| Security 4663 | File-system object access | Audit File System plus a matching SACL are required; do not enable broad SACL auditing on the whole disk just for this app |
| Security 4697 / 4698 | Service installation / scheduled-task creation | Relevant Advanced Audit Policy subcategories must be enabled |
| PowerShell 4104 / 4103 | Script Block / Module logging | Script Block Logging is needed for 4104; Module Logging is needed for 4103. The app does not silently enable these policies |
| Task Scheduler 106 / 140 / 141 / 200 / 201 | Task registration/update and task action lifecycle context | TaskScheduler Operational logging must be enabled and channel accessible |
| WMI Activity 5857–5861 | WMI provider / operation context | WMI Activity channel must exist and retain relevant events |

“Subscription active” means the application opened a subscription successfully. It does **not** mean the operating-system audit policy is enabled, that Sysmon is configured to emit every event, or that every possible action is recorded.

## Required targeted Sysmon configuration

Sysmon is mandatory for continuous monitoring. Launch TCTC Guardian normally; Python checks the sensor at startup and, when needed, downloads the official Microsoft Sysmon package, validates the ZIP, verifies the Authenticode signer through Windows Trust APIs, checks the schema and invokes Sysmon's documented CLI. The setup path does not launch PowerShell. A new installation uses the detect-only policy; no PE creation is blocked. The application requests license acceptance only when a new standalone Sysmon installation is required, and it uses the built-in Windows Sysmon optional feature if already enabled.

If another Sysmon configuration is already installed, the application asks before replacing it and saves the current `Sysmon -c` output as a backup. Do not approve that change on a centrally managed device without reviewing the existing policy. See `docs/SYSMON-REQUIRED.md`.

The targeted policy subscribes to ProcessCreate (1), Sysmon service state (4), FileCreate (11), Sysmon configuration change (16), FileDeleteDetected (26) and FileExecutableDetected (29) events. The application retains read-only compatibility handling for Event 27 if an older or externally managed policy emits it, but this release does not ship a FileBlockExecutable rule and does not configure Event 27. The app also polls service/channel/config-marker readiness every 10 seconds; Event 4 indicating stop or Event 16 indicating a config change immediately turns the tray state red and stops continuous monitoring until revalidation. Additional event types are scoped to the analyzed staging roots, Z797 process markers, confirmed campaign destinations and the three target processes. Sysmon Event 2 is also enabled for creation-time changes.

Current standalone Sysmon requirements are Windows 11 client or Windows Server 2019+. On Windows 10, the current official standalone release may not be supported; the app fails closed rather than silently installing an unsupported release. Microsoft also documents a built-in optional Sysmon feature on supported Windows 11 systems.

Official documentation: <https://learn.microsoft.com/sysinternals/downloads/sysmon>.

## PowerShell, Script Block Logging and AMSI


To enable Script Block Logging, use Group Policy:

`Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`.

Enable it only after considering privacy and log-volume implications. PowerShell logs can contain complete script text, arguments and secrets. Guardian redacts common password/token patterns in displayed excerpts, but administrators should still protect the underlying Windows Event Logs.

## Correlation and false-positive boundaries

- A process name such as `RuntimeBroker.exe`, `explorer.exe`, `chrome.exe`, `powershell.exe`, or `cmd.exe` is never sufficient for a detection or remediation.
- An exact artifact match requires a known SHA-256. For process-create events, the live file is also re-hashed and its byte size rechecked before the file is marked as currently verified or offered for quarantine.
- A filename such as `Z797.ps1` or a staging-path event without an exact hash is review-only and cannot be auto-quarantined.
- Parent/child process IDs are normalized, short-lived, and combined with Sysmon ProcessGuid where available. A fresh benign process record clears any previous suspicious state for a reused PID.
- Persistence changes become findings only when their target/action contains a sample marker, points to the exact staging path, or is created by an already-correlated process. No Registry, service or scheduled-task event triggers automatic deletion.
- A campaign IP or DNS name by itself is evidence for review, not an automatic block. Shared/reused infrastructure can appear in unrelated campaigns.
- Process behavior events (8/10/25) are attributed only from the actor side. Sysmon Event 10 must join its SourceProcessGuid, SourceImage and SourceProcessId to a retained ProcessCreate record with a sample-specific marker and a write-capable access mask. A benign process accessing Explorer/RuntimeBroker does not become a TCTC finding because of the target name. A descendant of a directly matched process is marked Medium confidence, not a direct High-confidence IOC match.


## Validation

Use synthetic XML fixtures and harmless staging files to test correlation. Do not execute the original sample or reconstructed payloads on a normal workstation. Complete `WINDOWS-VALIDATION.md` on a disposable Windows VM to validate actual provider subscriptions, event delivery, Sysmon schema compatibility, file notifications, and application shutdown behavior.

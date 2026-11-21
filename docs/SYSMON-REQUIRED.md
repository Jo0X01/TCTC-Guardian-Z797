# Required Sysmon sensor — TCTC Guardian Z797 v1.0.0

Sysmon is required for the continuous process/file event feed. Guardian does not describe periodic-only checks as complete real-time monitoring.

## Python-native setup

Users launch **TCTC Guardian Z797** only. The app checks the sensor during startup and prepares it internally when required. The normal installation flow does not invoke PowerShell.

1. The app requests Administrator elevation through the normal Windows UAC prompt.
2. Python checks the supported Windows baseline.
3. Python checks whether the Windows built-in Sysmon feature is already enabled. If so, it uses that sensor and does not install standalone Sysmon beside it.
4. Otherwise Python downloads `Sysmon.zip` only from `https://download.sysinternals.com/files/Sysmon.zip`, using the system proxy configuration available to Python.
5. Python validates archive size, entry count, CRC, path safety and architecture, extracts the expected executable, then validates Authenticode with Windows Trust APIs and requires Microsoft Corporation as signer.
6. Python runs the Sysmon CLI directly for schema inspection and install/configuration. Native stdout/stderr are captured separately; stderr text alone is not treated as failure when the process exit code is zero.
7. Guardian verifies service state, Operational channel availability and the active configuration marker/hash.

A standalone installation requires the user's acceptance of the Sysinternals license in the app. Existing externally managed configuration is backed up and is not replaced without explicit approval.

## Active policy

The default is **DETECT-ONLY**. The configuration includes `FileExecutableDetected` (Event 29) and does not include `FileBlockExecutable` (Event 27). Guardian does not block PE creation.

## Relevant events

The configuration supports process creation, process identity, file creation/deletion, PE creation detection, network/DNS and the process/memory correlation signals used by the analysed chain. Guardian further filters resulting history against the exact Z797 indicators and actor identity rules; a generic event type is not itself an infection finding.

## Operational limits

Subscriptions receive future records only; they do not replay history. Event availability depends on Sysmon/provider state, retention and permissions. Filesystem notifications begin after a write starts and do not provide pre-execution prevention. If Sysmon setup fails, manual investigation remains available but continuous monitoring is not marked ready.

The setup log is saved to `%LOCALAPPDATA%\TCTC Guardian Z797\Logs\sysmon-setup.log`.

## Validation

Use a disposable supported Windows machine and complete `WINDOWS-VALIDATION.md`. Linux tests cannot validate UAC, WinTrust, DISM, driver installation or live Event Log delivery.

Official references: [Sysmon download and usage](https://learn.microsoft.com/sysinternals/downloads/sysmon), [Windows Sysmon command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sysmon), [Windows built-in Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview), and [Microsoft Sysinternals license terms](https://learn.microsoft.com/en-us/sysinternals/license-terms).

# Detection map — TCTC / Z797 only

| Observed effect in the analysed chain | Guardian source | Z797 matching rule | Response boundary |
|---|---|---|---|
| ClickFix delivery and staged payloads | Two analysed Temp\Local roots; Sysmon file/process events | Exact SHA-256 + byte size, or exact `crandle.txt`, `Z797.ps1`, `tctc.bba` plus matching content/context | Exact payload may be auto-contained under the strict gate; marker-based files require confirmation |
| Process Ghosting / manual mapping | RuntimeBroker / Explorer process memory | Valid PE header inside private executable memory, strengthened by thread-start correlation | Evidence capture only; never kill a legitimate host from memory evidence alone |
| Suspended child / remote memory execution | Sysmon ProcessAccess / remote-thread history and live memory | Source actor must join by ProcessGuid + image + PID; write-capable access mask; exact campaign marker or confirmed lineage | Historical events are not cleanup targets; exact staged payload identity is needed for process containment |
| Explorer APC-style execution | Explorer memory and correlated process lineage | Private executable region plus thread-start evidence or independent actor-side sample correlation | Read-only evidence; no attempt to modify threads or queues |
| AMSI bypass stub | `amsi.dll` export bytes in sample-targeted processes | `AmsiScanBuffer` / `AmsiScanString` starts with the recovered return stub | Evidence only; no attempt to patch or restore live memory automatically |
| Z797 persistence | Run / RunOnce, Startup, Services, Scheduled Tasks | Current command or task/service image contains an exact Z797 URL, domain or recovered artifact reference | Revalidate exact current command, back up, then remove/disable only that item |
| C2 / delivery communication | Hosts file, DNS cache, active connections | Exact built-in domains/IPs; active connection promoted only when owning process is an exact recovered payload | Exact Hosts line can be removed with backup; exact-payload C2 connection can offer a confirmed Firewall rule; DNS/IP-only evidence is not blockable |
| Historical launch and script execution | Sysmon, Security, PowerShell 4103/4104, Task Scheduler, WMI | Exact Z797 indicators or complete source-actor identity join | Past event is evidence only; rescan current state before cleanup |
| ClickFix Run-dialog command | HKCU Explorer RunMRU | Exact Z797 URL/domain/artifact token | Read-only forensic history; never deleted because it does not relaunch the infection |

## Memory collection

Memory APIs are read-only. Suspicious regions are captured only when the enabled memory settings and evidence policy allow. A single executable private allocation or a COW page alone is not proof of this infection. Process image mismatches are low-confidence context. Protected processes, cross-bitness boundaries and inaccessible pages can reduce coverage.

## Network interpretation

A DNS cache row has no reliable initiating-process attribution and is displayed as Low-confidence historical context only. An active endpoint matching an IOC IP is not a Finding unless the owning process image is itself an exact recovered Z797 artifact (hash + size) in the analysed staging tree. Other IP-only endpoint rows are counted in coverage and suppressed from Findings.

## File cleanup gate

Before a file is quarantined Guardian checks that it is a regular non-reparse file in one of the two analysed staging roots or an approved Startup folder, that the current size and SHA-256 still match the Finding, and that the file either matches a recovered artifact fingerprint or actually contains an exact Z797 marker. A filename by itself is never enough.

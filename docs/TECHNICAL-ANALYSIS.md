> **Historical engineering notes:** This document preserves pre-public-release analysis and development context. Older version numbers below refer to internal development snapshots, not public GitHub releases.

# TCTC / LegionLoader: Technical Analysis and Defensive Findings

**Report revision:** 1.0  
**Research cut-off:** 21 November 2026  
**Platform:** Microsoft Windows, x64  
**Analysis basis:** supplied sample artifacts, reconstructed stages, static disassembly, offline decryption, recovered protocol data, and comparison with published research.

---

## 1. Executive summary

The investigated material describes a multi-stage ClickFix infection chain that uses a fake Cloudflare-style verification prompt to persuade a user to execute a command through the Windows Run dialog. The command retrieves an obfuscated PowerShell stage and a file named `tctc.bba`. The later stages decrypt and reconstruct a Windows payload in memory, perform environment checks, and load a task-driven controller.

The recovered controller is not simply a downloader. It contains a remote task framework with multiple ways to execute additional code, create processes, stage files, alter logon persistence, interact with other processes, and request Chrome-related key material. Several of the most consequential paths are implemented in native Windows code and are driven by task data returned by a remote server.

The strongest identifying link is the SHA-256 match between the recovered 494,080-byte inner controller and the controller recorded in ThreatFox IOC 2031306. The matching network configuration uses `benderoflight.com` with the `/nfront.php` registration/task endpoint and `/nback.php` result-reporting endpoint. Plume's 18 November 2026 report describes the same ClickFix delivery chain, the `tctc.bba` stage, and those LegionLoader C2 paths. ThreatFox labels its IOC metadata as Stealc, while Plume and other recent reporting describe the matching chain as LegionLoader. This report therefore uses **TCTC / LegionLoader chain** as a practical description and records the naming discrepancy rather than treating the family label as settled.

There is meaningful evidence of credential-access capability, particularly the Chrome key-retrieval helper. However, the evidence reviewed here does **not** establish that browser cookies, saved passwords, or personal files were successfully stolen or uploaded during the captured transaction. Nor does it establish that every task returned by the server was successfully executed. The risk is high because the operator can deliver further modules and payloads, not because every possible impact was observed.

The analysis was performed offline. No recovered malware, helper, or task payload was executed, and no suspected command-and-control or distribution endpoint was contacted.

## 2. Attribution and naming notes

The recovered inner controller has this SHA-256:

```text
a10e4fbff548ea2839db1cac5faaa3316b950cc9f8a2cf82658b1a9ad7eb9089
```

ThreatFox IOC 2031306 records `https://benderoflight.com/nfront.php`, first seen on 16 November 2026, and its attached offline analysis reports the same 494,080-byte controller hash and both C2 paths. ThreatFox's malware field labels that IOC **Stealc**. Plume's 18 November article describes the matching ClickFix chain and the controller as **LegionLoader**. eSentire's 20 November 2026 research documents a separate ROMULUS-based intrusion that also deploys LegionLoader and lists `benderoflight[.]com` among observed LegionLoader C2 domains.

These labels may reflect different stages, payloads, feed classifications, or reporting conventions. They should not be collapsed into a claim that the captured host definitely received Stealc, Amatera, Warden, or another named infostealer. The stable technical link for this investigation is the exact controller hash and the matching protocol configuration.

## 3. Scope and methodology

The review covered the outer executable, reconstructed worker/PIC material, the inner controller, selected task handlers, the C2 request/response material described in the supplied offline analysis, the recovered Chrome helper path, and the sample-specific Windows behavior used to design defensive checks.

The work relied on:

- PE structure inspection and hash verification.
- Static disassembly and call/data-flow review.
- Offline reconstruction and decryption of embedded stages already present in the evidence set.
- Review of a previously captured and decoded C2 transaction; the endpoint was not contacted.
- Comparison with vendor and threat-research reporting published before the report cut-off.

The complete virtual `.text` range of the recovered inner PE (`0x140001000` through `0x14005C648`, 374,344 bytes) has a linear disassembly with no byte-coverage gaps in the saved listing. That listing contains 94,243 address-labelled instruction/data rows. This is not the same as a full manual semantic review of every function. The `.pdata` table contains 1,600 runtime-function records; the behavior of every record has not been independently classified. Some methods are supplied through a dynamic module interface and their method bodies were not present in the recovered inner PE.

## 4. Infection chain

The observed chain can be summarized as follows:

```text
Fake Cloudflare / ClickFix prompt
          |
          v
User copies and runs a command through Win+R / cmd
          |
          v
Initial retrieval from 93.94.52.29
  - crandle.txt
  - Z797.ps1
          |
          v
Hidden, obfuscated PowerShell stage
  - displays a fake "CloudTrust Auth" window
  - retrieves encrypted tctc.bba
          |
          v
Decryption and in-memory execution stages
  - XTEA / AES layers in the recovered chain
  - environment checks
          |
          v
Recovered inner controller
  - registers with C2
  - receives task records
  - reports task results
          |
          v
Task-selected execution, process, file, persistence,
Chrome-helper, and dynamically supplied module paths
```

### 4.1 ClickFix delivery

The initial lure impersonates a Cloudflare human-verification step. Instead of completing a normal browser CAPTCHA, the page tells the user to open the Windows Run dialog, launch Command Prompt, paste clipboard content, and execute it. In the analyzed chain, the command retrieves `crandle.txt` and `Z797.ps1` from `93.94.52.29`.

`Z797.ps1` is heavily obfuscated. The documented chain reconstructs a smaller PowerShell script in memory, presents a fake verification window, retrieves the encrypted `tctc.bba` file, decrypts it, and starts the next stage. This is a social-engineering entry point: the user is tricked into running a command that a legitimate CAPTCHA would never require.

### 4.2 Environment checks

The recovered shellcode checks display-device information and asks `ipinfo.io` for public-IP/ASN information. It contains checks for virtual or remote display adapters and can stop when the public IP is classified as hosting infrastructure. These are anti-analysis gates. A matching query to `ipinfo.io` is contextual evidence, not a malicious indicator by itself.

### 4.3 Reconstructed stages

The investigation material records the following artifacts and hashes:

| Stage / artifact | Size | SHA-256 | Notes |
|---|---:|---|---|
| Original outer PE | 8,147,456 bytes | `077c93f044b590a017771ced5067e8adde18d629598ea545496904dafcfd8e22` | Outer stage from the supplied analysis set |
| Raw `tctc.bba` delivery file | 8,178,288 bytes | `c34719ff34d037eedc4338655d844734a7451c00250a56c8cba8f807f92bcafb` | Retrieved encrypted delivery artifact |
| Stage-2 shellcode | 8,328,272 bytes | `ce9263eec902131910d6ff69b33f2d61f09707dadb7818c11de46d97fa441169` | Recovered x64 shellcode stage |
| Generated stage-3 PE | 8,324,608 bytes | `30a16519c20df8f6d7fd8e127c5e2ba688b074eb723c60ed88e36b1da3cc1b12` | Reconstructed AMD64 PE |
| Inner C2 controller | 494,080 bytes | `a10e4fbff548ea2839db1cac5faaa3316b950cc9f8a2cf82658b1a9ad7eb9089` | Exact hash match to ThreatFox IOC analysis |
| `42.bin` encrypted transfer copy | 736,768 bytes | `4dd38c86f35b68702d47d3bb90c8dc694e9b85d179b0825fb1aea05d3e60a335` | From the published/offline PCAP analysis; not included in this repository |
| `42.bin` decrypted PE | 736,768 bytes | `4a5e0ed88529761af8e86afcf2b969217a7345abe2c467523d036bb5126ca644` | Recovered from the offline task capture; not included in this repository |

Hashes are included for defensive identification and cross-checking. This repository does not distribute the malware samples or reconstructed executable payloads.

## 5. Command-and-control protocol

The recovered controller is configured to communicate with `benderoflight.com` using two HTTP paths:

- `/nfront.php` — host registration and task retrieval.
- `/nback.php` — task-result/status reporting.

The reviewed protocol uses Base64 framing around RC4-transformed message bodies. The controller derives a device identifier from the volume serial number using a CRC32-based routine (the recovered BotID path performs five CRC32 rounds and formats the result as eight uppercase hexadecimal characters). The task records observed in the protocol have a fixed size of `0x48` bytes.

A previously captured offline transaction contains a registration request to `/nfront.php` and a response with five download tasks:

- `42.bin`
- `eeGai2ahyae.bin`
- `awpg2gawa2.fjk`
- `1488.bin`
- `just_test.bin`

The public/attached analysis recovered `42.bin` and reviewed its PE structure. The other four server-returned files were not available in the evidence set reviewed here. Their contents and purposes remain unknown. The task list demonstrates the controller's ability to receive remote tasking; it does not prove that every returned task ran successfully on a victim host.

The known network indicators are not guaranteed to be exhaustive. The controller can accept task-specific URLs and dynamically supplied module data, so later infrastructure may differ from the initial domain and paths.

## 6. Task-driven capabilities

The controller contains several distinct task paths. The subtype boundaries matter: treating every branch as one generic injection routine would obscure the actual implementation and overstate what is known.

### 6.1 PE, shellcode, script, and installer execution

The reviewed task handlers can stage and execute PE files, execute shellcode, run PowerShell-related tasks, and invoke MSI installation paths. The exact work performed by a downloaded payload depends on the task data and the payload itself. The mere presence of an execution handler does not prove that an unobserved payload was installed or executed.

### 6.2 RuntimeBroker manual mapping — Type 1 / subtype `0x0A`

This path starts a new `%SystemRoot%\\System32\\RuntimeBroker.exe` process suspended, stages an encrypted task-supplied PE and an embedded compact mapper, and redirects the suspended primary thread through a small trampoline. The helper decrypts and manually maps the task PE, resolves imports, applies relocations, and transfers control to its entry point.

This is a concrete custom manual-mapping path. It should not be described as classic process hollowing: the reviewed sequence does not show the original image being unmapped with `NtUnmapViewOfSection`. Static analysis establishes the intended code path, not successful execution on a particular Windows host.

### 6.3 Remote process memory path — Type 1 / subtype `0x0B`

A separate branch creates a suspended child process and performs remote allocation, memory writing, protection changes, and a thread-creation path involving `NtCreateThreadEx`. The analysis supports describing this as remote process-memory execution. It does not establish that this branch is the same as the RuntimeBroker manual mapper or that classic process hollowing occurs.

### 6.4 Process Ghosting-style path — Type 1 / subtype `0x11`

The reviewed sequence creates a temporary executable path, opens the file with read/write/delete access, marks it delete-pending, attempts to write the supplied PE bytes, creates a `SEC_IMAGE` section, closes the file handle, and passes the section to `NtCreateProcessEx`. It then calculates the mapped image entry point and calls `NtCreateThreadEx`.

This ordering strongly matches a Process Ghosting-style technique. There is an important runtime caveat: Microsoft documents file-disposition behavior and warns that subsequent I/O through a delete-pending handle is a programming error. The sample contains an explicit write attempt after the disposition call, but static code alone cannot establish whether the write and later process-creation steps succeed on the affected Windows version.

### 6.5 Separate native image-section process creation — Type 1 / subtype `0x12`

A further branch performs a native, file-backed process-creation path that is separate from the delete-pending flow above. It should not be merged with subtype `0x11` or called Process Ghosting without evidence of the same file lifecycle.

### 6.6 Explorer APC path — Type 3 / subtype `3`

The recovered code includes an APC-based path associated with a newly created Explorer process. It is distinct from the RuntimeBroker manual-mapping path. An intended APC handoff is a code-level capability; it is not proof that the target thread executed the callback on a real host.

### 6.7 AMSI tampering — Type 4

A separate task path prepares short stubs targeting `AmsiScanString` and `AmsiScanBuffer` in the RuntimeBroker-related flow. The analyzed stubs return a zero result. This supports describing an AMSI-tampering attempt. It does not prove that the bytes were successfully written, that AMSI was bypassed on a victim, or that all PowerShell activity was invisible.

### 6.8 File and module tasks

The reviewed task set includes file download/write/extraction operations, as well as additional memory-execution modes selected by task type. One archive extraction path has a path-confinement weakness: entries may be able to resolve outside the intended extraction directory. This is a security-relevant implementation issue in the controller; it is not proof that a particular victim file was overwritten.

The inner controller also includes a custom in-memory module runtime. It parses module dependency/import metadata and method-dispatch metadata, resolves exports using CRC32-style hashes, maps module data, runs an initializer, and dispatches task-specific methods by numeric identifier. At least two task families bridge into this module interface.

The module method bodies themselves are not fully represented in the recovered inner PE. Their inputs and dispatch relationships can be described, but their ultimate effects cannot be assigned names or assumed from the method identifiers alone. This is a major reason the controller must be treated as extensible and task-driven.

## 7. Persistence

The inner controller contains conditional writes to Windows `Run` and `RunOnce` locations. These are persistence capabilities, but the presence of the code does not prove that a persistence task was sent to, or successfully installed on, the captured host.

For defensive triage, registry values should be assessed by their complete command, target path, creation/modification context, and relationship to other sample indicators. An unfamiliar Run value on its own is not enough to attribute it to this malware.

## 8. Chrome-related key retrieval

The reviewed build includes two Chrome-related key paths.

### 8.1 Legacy `os_crypt.encrypted_key` path

The controller reads a staged Chrome `Local State` file under a `Temp\\Local` path, parses `os_crypt.encrypted_key`, Base64-decodes the value, and skips the five-byte `DPAPI` marker. The reviewed function does not show a subsequent `CryptUnprotectData` call. The recovered result should therefore be described as a DPAPI-wrapped key blob with its marker removed—not as a verified plaintext legacy master key.

### 8.2 App-Bound key helper

A separate helper starts Chrome in a suspended state, injects a helper into that process, and uses Chrome's `IElevator2Chrome::DecryptData` COM interface with the `app_bound_encrypted_key` material. The helper is designed to obtain a 32-byte key and return it over a local named pipe. The controller then writes returned data to a path supplied through task/configuration data.

The helper's named-pipe security descriptor is `D:(A;;GA;;;WD)`, which grants Generic-All rights to the World/Everyone SID. This is a weak IPC permission model if the dynamically generated pipe name becomes known.

### 8.3 Exfiltration boundary

The reviewed `nback.php` POST builder serializes task/status information. No direct data-flow edge was established from the Chrome key-output buffer or its destination file into that POST body. The key-retrieval capability is real in the code reviewed; a successful key extraction and subsequent upload are **not** proven by the evidence available for this transaction.

The reviewed core API hash table also did not reveal the common Windows APIs usually associated with conventional keylogging, screen capture, webcam/microphone recording, clipboard collection, or Windows Credential Manager enumeration. This does not rule out those capabilities in uncollected dynamic modules or later payloads.

## 9. What the evidence does not establish

The distinctions below are important for an accurate incident report:

- It does not establish successful theft of saved passwords, cookies, browser sessions, or personal documents.
- It does not establish that Chrome key material was uploaded to the known C2 endpoint.
- It does not establish that all five returned files were acquired or executed. Four of those files were unavailable for this review.
- It does not establish that every process-injection, APC, AMSI, Ghosting, or manual-mapping path succeeded at runtime.
- It does not establish ransomware behavior, mass file encryption, mass deletion, or destructive wiping.
- It does not establish conventional keylogging, screen recording, webcam capture, or microphone recording in the recovered core controller.
- It does not establish that the C2 domain and its IP addresses are the complete or permanent infrastructure for this operator or family.

These are limits of the evidence, not assurances that the activities could never occur. The remote task model and missing modules leave room for behavior that was not captured in the supplied artifacts.

## 10. Defensive implications

A suspected execution of this chain should be handled as a security incident, not as a simple request to delete one file.

1. **Isolate the host** from untrusted networks while preserving the option to collect evidence.
2. **Preserve the timeline and artifacts** before removing files or changing persistence. Record process identifiers, image paths, hashes, event-log records, DNS cache, hosts-file contents, and active endpoints.
3. **Review the process graph.** Pay particular attention to processes launched from the sample's `Temp\\Local` staging pattern, abnormal child-process relationships, suspicious RuntimeBroker instances, and activity involving Explorer or Chrome. Do not terminate a legitimate `C:\\Windows\\System32\\RuntimeBroker.exe` merely because its name appears in the report.
4. **Inspect persistence precisely.** Review only the specific Run/RunOnce values, scheduled tasks, services, and Startup entries supported by evidence. Back up the exact configuration before changing it.
5. **Preserve network evidence.** Record the DNS resolver cache, Hosts mappings, current sockets, and relevant firewall events. Do not contact the suspected server to "check" whether it is live.
7. **Consider rebuild.** If the host has confirmed execution and unresolved persistence or process compromise, rebuilding Windows from trusted media may be more reliable than attempting to prove complete cleanup.

A clean targeted scan means only that the configured indicators were not found in the sources that could be read. It is not proof of complete eradication.

## 11. Mapping the findings to TCTC Guardian Z797


### Implemented in v0.8.2

- Targeted checks for active processes and suspicious image paths, especially the sample's `Temp\Local` staging pattern.
- Checks for Run/RunOnce, services, Startup folders, and scheduled-task actions.
- Focused review of the known staging directories and any additional directories explicitly supplied by the user.
- Streaming SHA-256 and marker matching without an arbitrary file-count or individual-file size ceiling.
- Local DNS-cache, Hosts, default gateway/DNS configuration, and current TCP/UDP endpoint review. Configured domains are not resolved and no C2 traffic is sent.
- User-editable domain, IP, URL/path, port and custom-root indicators, with local JSON Threat Profile import/export.
- Optional in-app repeat checks for process, memory, persistence, targeted staging and network state while the UI remains open.
- Evidence-oriented findings, confidence labels, HTML/JSON reports, local audit logs, constrained remediation, quarantine and backups where supported.
- Mandatory Administrator elevation on Windows, a new application icon and the redesigned dark UI.

### Not implemented or not complete in this package

- A persistent Windows monitoring service or service-based monitoring after the UI closes.
- Historical APC queue/delivery reconstruction from a current process-memory snapshot.
- Full byte-for-byte verification of every mapped module against a trusted disk image; the implemented integrity checks are copy-on-write hints and the sample-relevant AMSI export stub check.
- A complete Process Ghosting sensor based on section-object identity and historical process-creation telemetry. The current collector adds only a low-confidence mapped-image path / file-visibility hint.
- A persistent Windows service and monitoring after application exit. The push subscriptions only run while the app is open and receive future records; historical inspection remains periodic.
- The current release includes read-only process-memory inspection, private executable region capture, optional per-action-consent full-process dumps, and evidence-first whole-process containment for qualifying high-confidence findings.
- The current release also supports a narrowly-scoped outbound Firewall block for a high-confidence remote IP correlated with the known staging process, with exact-rule verification, backup, rollback and managed-rule removal. Complete DNS adapter restoration remains incomplete.
- Signed remote Threat Profile updates, an automatic updater, an executable custom-rule engine, and evidence-at-rest encryption.
- A persistent Windows service that continues collecting after the UI closes; startup registration is implemented through a per-user Scheduled Task, not a service.
- Full application localization; the current interface is English and Arabic UI resources have not been implemented.

The Memory workspace exposes the implemented read-only collector. A mapped-PE or thread-correlated region can be captured with process metadata, capture time and SHA-256 before any supported containment action. The collector never changes target page protection or patches code. Under Ask policy, containment requires explicit confirmation; Auto policy can terminate only a qualifying High-confidence process after the complete capture and PID/image-path re-check. It terminates the entire process, not one arbitrary page.

### Current scan scope limits

The `v0.8.2` interface exposes one sample-specific investigation action. Targeted traversal is limited by default to the exact Temp\Local locations associated with the sample and any additional roots explicitly supplied by the user. File enumeration, SHA-256 hashing and marker matching are streamed without an arbitrary entry-count or individual-file size ceiling. The release now includes a read-only live process-memory collector and local evidence capture, but it does not include a persistent Windows monitoring service. Memory APIs still require validation on Windows 10/11; see `IMPLEMENTATION-STATUS.md` and `WINDOWS-VALIDATION.md`.

### Build and validation status


## 12. Indicators of compromise

The indicators below are defanged to reduce accidental navigation. They are historical indicators from the analyzed chain, not a guarantee that the infrastructure remains active or exhaustive.

### Network

| Indicator | Context |
|---|---|
| `benderoflight[.]com` | Inner controller C2 domain recorded in the recovered PE |
| `hxxps://benderoflight[.]com/nfront.php` | Registration / task retrieval |
| `hxxps://benderoflight[.]com/nback.php` | Task-result reporting |
| `93[.]94[.]52[.]29` | Initial ClickFix delivery IP in the analyzed chain |
| `survivomatic[.]com` | Host for the `42.bin` task in the decoded response |
| `ruthaiv[.]com` | Host for other task files in the decoded response |
| `ipinfo[.]io` | Anti-analysis / hosting-ASN check; contextual only, not malicious by itself |

### File hashes

See Section 4.3 for the seven reconstructed/referenced artifact hashes. Hashes belonging to the `42.bin` PCAP analysis are published evidence references and do not indicate that those payload bytes are bundled with this project.

### Sample-specific behavioral indicators

- Staging under `%TEMP%\\Local` and `%WINDIR%\\Temp\\Local`.
- Registry Run/RunOnce writes using task-controlled commands.
- The controller strings `/nfront.php` and `/nback.php`.
- AMSI function names `AmsiScanString` and `AmsiScanBuffer` in the context of suspicious process-access/memory evidence.
- RuntimeBroker, Explorer, or Chrome activity only when correlated with process ancestry, unusual image paths, memory evidence, or related file/network indicators. The process name alone is not an IOC.

## 13. Recent public research considered

The following publications were available during the investigation and were reviewed for context. The two most recent reports are particularly relevant to the timing of this analysis:

1. **eSentire Threat Response Unit — 20 November 2026**, [ROMULUS ClickFix to LegionLoader and Warden Stealer: Breaking Down a Multi-Stage Malware Intrusion](https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion). This is a separate ROMULUS/MSI-based intrusion, not the exact `tctc.bba` delivery chain analysed here. It independently documents a recent LegionLoader deployment, CRC32-based module/API hashing, RC4/Base64 C2 messaging, `nfront.php` / `nback.php`, and lists `benderoflight[.]com` among observed LegionLoader C2 domains.
2. **Plume Security Lab — 18 November 2026**, [Before GTA VI](https://www.plume.com/newsroom/before-gta-vi). This is the closest recent public match to the investigated chain: fake Cloudflare ClickFix instructions, `crandle.txt`, `Z797.ps1`, encrypted `tctc.bba`, in-memory stages, anti-analysis checks, and LegionLoader communication over `nfront.php` / `nback.php`.
3. **ThreatFox / abuse.ch — IOC 2031306, reported 16 November 2026**, [https://threatfox.abuse.ch/ioc/2031306/](https://threatfox.abuse.ch/ioc/2031306/). The entry records the `benderoflight[.]com/nfront.php` URL and an offline analysis that identifies the exact 494,080-byte controller hash used in this report. Its malware metadata field says Stealc; the naming difference is described in Section 2.
4. **Forescout Vedere Labs — 15 October 2026**, [ROMULUS: Analysis of a New Multi-Payload ClickFix Delivery Platform](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/). Broader context on ClickFix delivery infrastructure and a separate LegionLoader delivery route. It should not be used to attribute every ROMULUS indicator to the sample in this report.
5. **AhnLab ASEC — 3 September 2026**, [I just trusted the security certificate prompt… Beware of the LegionLoader malware being distributed via the ClickFix method](https://asec.ahnlab.com/en/95374/). Family-level context for fake Cloudflare prompts, staged execution, payload tasking, and Chrome key/browser-profile capabilities. It is supporting research, not proof that every reported family behavior occurred in this captured transaction.
6. **Elastic Security — 15 June 2021**, [What you need to know about Process Ghosting](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack). Background reference for the delete-pending file and image-section sequence used to classify the Type 1 / subtype `0x11` path.
7. **Microsoft Learn**, [`NtSetInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile) and [`FILE_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class). Primary documentation used for the delete-pending / file-disposition caveat.

---

## 14. Final assessment

The investigated controller is a capable, task-driven Windows backdoor/loader with multiple process-creation and memory-execution paths, conditional persistence, file operations, a dynamic module interface, and Chrome key-retrieval functionality. Its ability to receive further tasking makes the compromise potentially broader than the files visible during a single scan.

The correct defensive position is to treat confirmed execution as a high-risk incident, preserve evidence, isolate the host, review persistence and process lineage, and use trusted remediation or rebuild procedures as appropriate. Claims of successful credential theft, exfiltration, ransomware, or complete cleanup should be made only when supported by additional evidence.


### Pre-execution prevention limits (v0.9.3)

- The local filesystem observer detects create/modify notifications after a write starts; it cannot guarantee interception before first execution.


### v0.9.4 operational changes

Sysmon is a mandatory prerequisite for continuous monitoring. The launcher verifies the Microsoft-signed Sysmon installation and applies the scoped Z797 event policy. Exact known sample binaries can be stopped and quarantined when live event telemetry and a current on-disk SHA-256 + exact-size check agree. This is early post-launch containment, not a pre-execution block; Sysmon itself only records events and does not block activity.

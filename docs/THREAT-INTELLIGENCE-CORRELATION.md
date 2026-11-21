# Z797 / TCTC Threat-Intelligence Correlation

**Scope:** defensive detection engineering for the locally analysed Z797 / TCTC sample. This document separates direct campaign reporting from family-level and sibling-campaign context. Published indicators from other campaigns must not be silently imported into the Z797 profile.

## 1. Closest public reporting for the same delivery chain

### Plume Security Lab — Before GTA VI

https://www.plume.com/newsroom/before-gta-vi

This is the closest public report for the chain investigated here: fake Cloudflare / ClickFix instructions, `crandle.txt`, `Z797.ps1`, fake CloudTrust Auth, encrypted `tctc.bba`, in-memory stages, and the LegionLoader controller flow. It supports the specific delivery naming and broad chain model used by the Z797 profile.

### ThreatFox / abuse.ch — IOC 2031306

https://threatfox.abuse.ch/ioc/2031306/

An IOC entry associated with the controller endpoint and the hash relationship described in the local research report. ThreatFox's malware-family tag differs from the LegionLoader naming in the Plume report. The product should preserve this source-label disagreement instead of pretending that one public label resolves all taxonomy.

## 2. Related family behavior — not an IOC source for this sample

### AhnLab ASEC — ClickFix-delivered LegionLoader

https://asec.ahnlab.com/en/95374/

Adds family-level defensive context around fake CAPTCHA/ClickFix delivery, PowerShell stages, VM/hosting-environment checks, process injection / hollowing, AMSI interference, browser-key capability, and Run/RunOnce persistence. The published campaign has different delivery infrastructure and C2 domains. Its IPs, domains, hashes and campaign filenames are not part of the Z797 IOC set unless independently observed in local evidence.

### Forescout Vedere Labs — ROMULUS multi-payload ClickFix platform

https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/

Provides broader delivery-platform context. It describes related ClickFix / multi-payload patterns but is not proof that every ROMULUS payload, domain or persistence mechanism occurred in the Z797 incident.

### eSentire TRU — ROMULUS → LegionLoader → Warden Stealer

https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion

Describes a separate intrusion chain and a different follow-on payload. Techniques involving MSI, callbacks and process hollowing can inform behavioral telemetry priorities, but Warden-specific indicators and process names are not automatically Z797 indicators.

### ChamX — Inside a ROMULUS Campaign

https://cham1ndux.github.io/posts/Inside-a-Romulus-Campaign/

Provides additional technical analysis of MSI extraction, thread-pool callback execution, decimal-encoded IPv4 hosts, and Chrome key staging. These are used only as low-confidence behavioral context unless the same evidence appears in the local Z797 endpoint telemetry. The reported campaign's domains, IP addresses and build-specific hashes must not be merged into this sample's profile.

### Blackpoint Cyber — CNCMachineRMS: The Missing Piece in the ROMULUS Campaign

https://blackpointcyber.com/blog/romulus-cncmachinerms/

Published November 18, 2026. This report explicitly separates a ROMULUS route delivering LegionLoader from a different Stardock/MSI route delivering CNCMachineRMS. It provides broader hunting context for PowerShell-to-MSI execution, DLL sideloading, combined Run-key and scheduled-task persistence, and DNS-over-HTTPS. Its installer names, DLLs, hashes, task names and IP addresses are not Z797 indicators.

### OSec — Weekly situation report: 10/26/26

https://www.osec.com/resources/threat-briefs/weekly-situation-report-10-26-26/

Published October 29, 2026. Its coverage of a separate Siemens/ROMULUS ClickFix variant recommends reviewing the Windows `RunMRU` history for encoded commands and downloads. The application uses that as a read-only forensic source for possible ClickFix launch traces, not as evidence that the Siemens installer or its persistence names were used in the local Z797 chain.

## 3. Default IP profile and provenance policy

The application now ships with a two-tier IP profile. The tiers are intentionally separate; only the first tier can enter the normal Z797 endpoint-response path.

### Confirmed Z797-associated addresses

| Address | Role | Evidence / response boundary |
|---|---|---|
| `93.94.52.29` | Initial ClickFix delivery host for `/454`, `/455`, `crandle.txt`, `Z797.ps1`, and `tctc.bba` | Directly documented in the Plume report and the ThreatFox IOC 2031306 analysis. It is a delivery host, not the recovered controller endpoint. |
| `109.238.86.137` | Destination of the locally recovered TLS transaction for `POST /nfront.php` on `benderoflight.com` | Recorded in the local PCAP analysis and in the detailed ThreatFox IOC 2031306 report. ThreatFox later also recorded this address in a separate ROMULUS/OnionDrop ClickFix report (IOC 2008856), so address reuse is possible. A sighting without a matching process/domain context is not proof of this Z797 incident. |

Both addresses are included in the default **confirmed Z797 delivery / C2 IP** list. An endpoint-only match is still a review finding; the high-confidence containment path requires correlation to a process under the sample-specific staging tree. Firewall response is separately controlled by the user's policy.

### Related-report addresses — context only

These addresses are shipped in a distinct watch-only list. They can create a Low-confidence `Network context` finding when seen as a remote endpoint, but they are never offered for Firewall blocking, process termination, or quarantine by this product.

| Address(es) | Source / scope distinction |
|---|---|
| `93.94.52.4` | URLhaus records a `tctc.bba` URL on this host, but its reported payload SHA-256 (`f8b529…`) differs from the locally analysed `tctc.bba` hash. Treat as a possible separate variant, not an exact Z797 match. |
| `89.34.90.217` | AhnLab's separate ClickFix / LegionLoader campaign. |
| `96.62.224.81`, `86.109.75.7`, `151.240.151.223`, `23.94.145.224`, `93.152.224.118`, `2.27.248.127` | Forescout's six ROMULUS infrastructure addresses; related delivery platform / sibling campaigns, not the same Z797 infrastructure. |
| `23.94.252.153` | eSentire's separate ROMULUS MSI-to-LegionLoader-to-Warden chain. |
| `167.76.44.160`, `167.148.201.224`, `93.152.213.151`, `86.107.124.7` | Blackpoint's ROMULUS / CNCMachineRMS route and related infrastructure; distinct follow-on payload chain. |

Shared Cloudflare edge addresses observed for task-download hosts are deliberately excluded. They are CDN infrastructure and are not treated as origin-server or campaign IOCs. In particular, `172.67.207.16` and the reported `104.21.*` / `188.114.*` edge addresses must not be added to a blocklist based solely on these reports.

Sources: [Plume](https://www.plume.com/newsroom/before-gta-vi), [ThreatFox IOC 2031306](https://threatfox.abuse.ch/ioc/2031306/), [ThreatFox IOC 2008856](https://threatfox.abuse.ch/ioc/2008856/), [URLhaus 93.94.52.4](https://urlhaus.abuse.ch/host/93.94.52.4/), [AhnLab](https://asec.ahnlab.com/en/95374/), [Forescout ROMULUS coverage](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/), [eSentire](https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion), [Blackpoint Cyber](https://blackpointcyber.com/blog/romulus-cncmachinerms/).

## 4. Defensive additions used by the application

| Behavior | Current detection/response treatment | Confidence boundary |
|---|---|---|
| Hidden or encoded PowerShell with download/staging context | Match available process-creation telemetry and relevant paths/tokens | Requires command-line auditing / Sysmon Event 1 or equivalent; command-line fragments alone are not proof |
| `msi.dll` / Windows Installer activity from a script host | Contextual match in available image-load / process telemetry | Loading `msi.dll` is not malicious by itself; correlate parent, command line, file origin and child process |
| Process-access / tampering involving target processes | Correlate Sysmon ProcessAccess, CreateRemoteThread and ProcessTampering events where available | Sysmon visibility depends on configuration; absence of an event is not evidence that no injection occurred |
| Thread-pool callback API names | Match only if such names are actually present in collected EDR/ETW/other telemetry | Sysmon does not log every API call; no claim of universal callback detection |
| Decimal-encoded IPv4 in script download context | Low-confidence contextual heuristic only | Not a Z797 IOC; validate the decoded address and process lineage before action |
| Chrome profile access | Review available file-access / process-access records and exact known helper staging paths; exact staged helper outputs may be manually quarantined after hashing | The application does not read Chrome Local State, cookies, password stores or history contents; original browser profile files are not cleaned |
| `Svie24xHm5.png`, `jaw9Bytr4W.png`, `ifwf.e4` | Metadata/hash and location review; the two Chrome helpers are manual-only quarantine candidates at the exact local staging path | Filenames from related reporting are contextual; matches outside the exact path remain low confidence; `ifwf.e4` is not auto-quarantined |
| Windows RunMRU | Read-only inspection of matching Run-dialog command history | Exact Z797 strings receive higher confidence; generic encoded/download PowerShell is contextual; entries are never modified or removed |

## 5. Local-analysis evidence remains separate

The internal reverse-engineering report and local artifact verification log are original project evidence. They are not external publications. The following local findings remain distinct from the public reports:

- Exact hashes for the locally recovered outer PE, inner controller and intermediate artifacts.
- `benderoflight.com` with `/nfront.php` and `/nback.php` as the locally recovered controller endpoints.
- The local `Temp\Local` staging paths and Chrome-helper artifact paths observed during the analysis.
- The process/memory behavior classifications recovered from the local sample's static analysis.

The local report also records unresolved differences between some local wrapper hashes/keys and the published report, as well as remaining reproducibility work for the first transformation from raw `tctc.bba`. Do not state that every layer is byte-identical across reports.

## 6. What event logs cannot tell the application

- Sysmon and Security Event Log are not universal API-call tracers.
- Historical APC queue contents cannot be queried from a process snapshot after the fact.
- Thread-pool callback dispatch and indirect syscall behavior may need preconfigured ETW/EDR instrumentation or a trusted specialized sensor.
- If the relevant provider/audit policy was disabled before the incident, the historical action may not exist in local logs.

The app must surface missing telemetry as a coverage gap, not interpret it as a clean result.

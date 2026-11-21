# Safe validation plan

## Do not run the live sample on a daily-use Windows installation

The investigated Z797/TCTC chain includes process injection and in-memory execution paths, staged payloads, persistence logic, and outbound tasking. Running it on a normal workstation can compromise that workstation and nearby systems. This repository does not provide instructions to execute the live sample.

## What the repository can validate safely

- Unit tests exercise exact SHA-256 + size matching, staging-name/path rules, RunMRU parsing, remote endpoint correlation, memory parsing, confidence rules, quarantine verification, and rollback logic.
- Memory tests use mocked Windows APIs and inert byte buffers; they do not inject code into processes.
- Event-log behavior tests use synthetic log records; they do not create malicious processes or persistence.
- Tray-state tests verify green/active and red/stopped status decisions without requiring the Qt runtime.

Run on a development machine:

```bat
Validate-Project.bat
```

## Dynamic analysis boundary

If a real sample must be dynamically analysed, that work belongs in a purpose-built malware-analysis lab operated by a qualified analyst. Use a disposable, isolated environment with a recoverable snapshot and no bridge to production networks or personal devices. Do not enable shared folders, shared clipboard, credential passthrough, or host-mounted writable storage. Do not allow the sample to reach its real command-and-control or delivery infrastructure. Follow the lab's established containment and evidence-handling procedures.

A VM snapshot alone is not a guarantee of containment. Do not treat a successful unit test or a clean targeted scan as proof that a live infection was fully prevented or eradicated.

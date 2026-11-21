# Contributing

Thanks for helping improve TCTC Guardian Z797.

## Project scope

Contributions must preserve the project's narrow defensive purpose: investigate, monitor, and clean verified effects of the specifically analysed TCTC / Z797 chain. This is not a general-purpose antivirus.

Do not contribute functionality for malware execution, stealth, evasion, process injection, remote-memory writes, AMSI tampering, credential theft, persistence deployment, C2 communication, or destructive testing. Do not add unrelated campaign indicators without a documented, verifiable analysis basis.

## Before opening a pull request

1. Explain the bug or defensive use case and the exact scan/response stage affected.
2. Add or update focused unit tests. Windows API behavior must be isolated behind testable wrappers and mocked for portable tests.
3. Run:

   ```bash
   python -m compileall -q src tests
   python src/main.py --self-check
   python -m unittest discover -s tests -t . -v
   ```

4. Update the relevant English and Arabic documentation when user-visible behavior changes.
5. State clearly which checks were run on Linux and which were verified on real Windows. Do not describe mocked Windows API tests as live Windows validation.

## Security and privacy

Never include live malware, extracted payloads, shellcode, memory dumps, PCAP captures, credentials, personal user data, or unredacted endpoint logs in issues or pull requests. Follow [SECURITY.md](SECURITY.md) for sensitive reports.

## Licensing
**The original TCTC Guardian Z797 project code is not offered under the GNU General Public License or any other open-source license. All rights are reserved.** No permission to copy, modify, sublicense, publish, redistribute, or incorporate the project code into another product is granted by making this repository public. Obtain written permission from the project owner before reusing the original project code.

Licenses belonging to third-party components (for example Python, Qt/PySide6, and watchdog) apply only to those respective components. They do not grant a license to the original TCTC Guardian Z797 code. Microsoft Sysmon is downloaded separately from Microsoft and is not included in this repository.

The repository intentionally uses [`LICENSE-PENDING.md`](LICENSE-PENDING.md) to record that no standard open-source license has been selected. **Do not add a GPL-3.0 `LICENSE` file unless the project owner explicitly changes this decision.** See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for component-specific notices.
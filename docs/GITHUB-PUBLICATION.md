# GitHub publication checklist

## Repository

- Suggested repository name: `TCTC-Guardian-Z797`
- Suggested description: `Targeted Windows detection, monitoring, and cleanup for the analysed TCTC/Z797 ClickFix chain.`
- Recommended default branch: `main`
- Initial public tag: `v1.0.0`
- The repository includes English and Arabic READMEs, contribution guidance, a security policy, issue templates, and a GitHub Actions test workflow.

## Visibility and license

The project owner must choose repository visibility. The source currently has no selected open-source license; `LICENSE-PENDING.md` records the temporary all-rights-reserved status. A public GitHub repository without a `LICENSE` file does not grant general reuse rights; the current project notice is all rights reserved. Do not add MIT, GPL, Apache-2.0, or another license without the owner's explicit decision.

## Initial release assets

- `TCTC-Guardian-Z797-v1.0.0-GitHub-Package.zip` — source package.
- `TCTC-Guardian-Z797-v1.0.0-GitHub-Package.zip.sha256` — SHA-256 checksum.
- Release description: `RELEASE-NOTES-v1.0.0.md`.

## Before publishing

- Review the final file list and confirm no local reports, logs, quarantine items, backups, memory dumps, packet captures, credentials, or sample payloads are present.
- Confirm third-party license notices are accurate for the actual modules and distribution.
- Run GitHub Actions on both Ubuntu and Windows. A passing CI run is still not proof of successful Sysmon installation, live memory collection, native event delivery, or remediation on Windows.
- Complete `docs/WINDOWS-VALIDATION.md` on a disposable Windows test machine before distributing a binary or relying on live response.

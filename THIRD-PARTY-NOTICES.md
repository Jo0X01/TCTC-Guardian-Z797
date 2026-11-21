# Third-party notices

TCTC Guardian Z797 is built with the following third-party components and operating-system interfaces:

- **Python** — PSF License. https://docs.python.org/3/license.html
- **PySide6 / Qt for Python** — licensing depends on the selected modules and distribution model. Review the official licensing notes before distributing a binary: https://doc.qt.io/qtforpython-6/licenses.html
- **watchdog** — Python filesystem notification package; review its bundled license metadata when producing a distribution.
- **Nuitka** — optional build tool: https://nuitka.net/
- **Microsoft Sysmon** — downloaded from the official Microsoft endpoint at runtime; it is not bundled or redistributed in this source package. Review https://learn.microsoft.com/en-us/sysinternals/license-terms and https://learn.microsoft.com/en-us/sysinternals/license-faq.
- **Windows APIs / Event Log / Task Scheduler / Registry / Firewall interfaces** — built-in operating-system interfaces; no external vendor SDK is bundled for these APIs.

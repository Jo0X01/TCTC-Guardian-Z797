from __future__ import annotations
import json, subprocess, os, re
from typing import Any

KNOWN_DOMAIN = "benderoflight.com"
KNOWN_PATHS = ["/nfront.php", "/nback.php"]


def _run(args: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def collect_network_diagnostics(
    endpoint_limit: int = 500,
    domains: list[str] | None = None,
    api_paths: list[str] | None = None,
    ips: list[str] | None = None,
    ports: list[str] | None = None,
) -> dict[str, Any]:
    """Passive local diagnostics only. Never sends HTTP requests to malware C2."""
    endpoint_limit = max(100, min(int(endpoint_limit), 2000))
    source_domains = [KNOWN_DOMAIN] if domains is None else domains
    configured_domains = list(
        dict.fromkeys(x.strip().lower() for x in source_domains if x.strip())
    )
    configured_paths = list(
        dict.fromkeys(
            x.strip()
            for x in (KNOWN_PATHS if api_paths is None else api_paths)
            if x.strip()
        )
    )
    configured_ips = list(dict.fromkeys(x.strip() for x in (ips or []) if x.strip()))
    configured_ports = list(
        dict.fromkeys(str(x).strip() for x in (ports or []) if str(x).strip())
    )
    r = {
        "default_dns": [],
        "default_gateway": [],
        "endpoints": [],
        "known_server": {
            "domains": configured_domains,
            "ips": configured_ips,
            "api_paths": configured_paths,
            "ports": configured_ports,
            "policy": "Local telemetry only; no DNS lookup, HTTP request or API request is sent to configured indicators.",
        },
        "dns_resolution": {
            "status": "not_queried_for_safety",
            "addresses": [],
            "error": "C2 indicators are not resolved by this tool.",
        },
        "hosts_matches": [],
        "errors": [],
        "collection_status": "collected",
    }
    if os.name != "nt":
        r["errors"].append("Windows-only diagnostics")
        return r
    rc, out, err = _run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses} | Select-Object -ExpandProperty ServerAddresses | Sort-Object -Unique | ConvertTo-Json -Compress",
        ]
    )
    if rc == 0:
        try:
            v = json.loads(out or "[]")
            r["default_dns"] = v if isinstance(v, list) else [v]
        except Exception as e:
            r["errors"].append(f"DNS adapter parsing: {e}")
    else:
        r["errors"].append(f"Could not query configured DNS servers: {err or out}")
    rc, out, err = _run(["ipconfig.exe", "/all"])
    if rc == 0:
        for line in out.splitlines():
            if re.search(r"Default Gateway", line, re.I) and ":" in line:
                v = line.split(":", 1)[1].strip()
                if v:
                    r["default_gateway"].append(v)
    else:
        r["errors"].append(f"ipconfig unavailable: {err or out}")
    rc, out, err = _run(["netstat.exe", "-ano"], 20)
    if rc == 0:
        r["endpoints"] = [
            x.strip() for x in out.splitlines() if re.search(r"\b(TCP|UDP)\b", x, re.I)
        ][:endpoint_limit]
    else:
        r["errors"].append(f"netstat unavailable: {err or out}")
    hosts = os.path.join(
        os.environ.get("WINDIR", r"C:\\Windows"), "System32", "drivers", "etc", "hosts"
    )
    try:
        with open(hosts, "r", encoding="utf-8", errors="replace") as f:
            r["hosts_matches"] = [
                x.strip()
                for x in f
                if any(d in x.lower() for d in configured_domains)
                and not x.lstrip().startswith("#")
            ]
    except Exception as e:
        r["errors"].append(f"Hosts file unavailable: {e}")
    return r

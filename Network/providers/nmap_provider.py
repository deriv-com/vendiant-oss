"""
Provider that wraps a locally installed ``nmap`` binary.

Runs ``nmap -sV -Pn --open`` against the host and parses the XML output.
Nmap must be on ``PATH`` (or set ``NMAP_PATH``). Version detection (``-sV``)
gives much better product/version data than the built-in socket scanner.

Configuration (environment variables):

``NMAP_PATH``   Path to the nmap executable (default ``nmap``).
``NMAP_PORTS``  Port spec passed to ``-p`` (default: the same list as the
                socket provider, or ``NETWORK_SCAN_PORTS`` if set).
``NMAP_ARGS``   Extra arguments appended to the command line, e.g.
                ``--version-light -T4``.
``NMAP_TIMEOUT``  Seconds to wait for nmap per host (default ``300``).

Note: nmap needs raw-socket privileges for SYN scans; the default
``-sV`` connect scan works unprivileged.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Optional

from .base import (
    DEFAULT_SCAN_PORTS,
    HostScanResult,
    NetworkScanError,
    NetworkScanProvider,
    ServiceInfo,
)


class NmapScanProvider(NetworkScanProvider):
    name = "nmap"
    request_interval_seconds = 0.0

    def __init__(self) -> None:
        self.binary = os.getenv("NMAP_PATH", "nmap")
        ports = os.getenv("NMAP_PORTS") or os.getenv("NETWORK_SCAN_PORTS")
        self.ports = ports or ",".join(str(p) for p in DEFAULT_SCAN_PORTS)
        self.extra_args = shlex.split(os.getenv("NMAP_ARGS", ""))
        self.timeout = int(os.getenv("NMAP_TIMEOUT", "300"))

    def validate_config(self) -> None:
        if shutil.which(self.binary) is None:
            raise NetworkScanError(
                f"nmap binary '{self.binary}' not found. Install nmap or set NMAP_PATH."
            )

    def scan_host(self, ip: str, hostname: Optional[str] = None) -> HostScanResult:
        cmd: List[str] = [
            self.binary, "-sV", "-Pn", "--open", "-p", self.ports, "-oX", "-", *self.extra_args, ip,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except FileNotFoundError as exc:
            raise NetworkScanError(f"nmap binary '{self.binary}' not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise NetworkScanError(f"nmap timed out after {self.timeout}s for {ip}") from exc

        if proc.returncode != 0:
            raise NetworkScanError(
                f"nmap exited with {proc.returncode} for {ip}: {proc.stderr.strip()[:200]}"
            )

        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError as exc:
            raise NetworkScanError(f"could not parse nmap XML for {ip}: {exc}") from exc

        services: List[ServiceInfo] = []
        for port_el in root.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(port_el.get("portid", "0"))
            svc = port_el.find("service")
            product = version = banner = ""
            if svc is not None:
                product = svc.get("product") or svc.get("name") or "Unknown"
                version = svc.get("version") or ""
                extra = svc.get("extrainfo") or ""
                banner = " ".join(x for x in (product, version, extra) if x).strip()
            vulns: List[str] = []
            for script in port_el.iter("script"):
                if script.get("id") in ("vulners", "vuln"):
                    out = script.get("output") or ""
                    vulns.extend(sorted({t for t in out.split() if t.startswith("CVE-")}))
            services.append(
                ServiceInfo(
                    port=port,
                    transport=port_el.get("protocol", "tcp"),
                    product=product or "Unknown",
                    version=version,
                    banner=banner,
                    vulns=vulns,
                )
            )

        return HostScanResult(ip=ip, ports=[s.port for s in services], services=services, raw=None)

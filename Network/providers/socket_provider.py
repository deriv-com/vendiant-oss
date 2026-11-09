"""
Built-in TCP connect scanner.

Zero dependencies and no API key: it opens a TCP connection to each
configured port, records the ones that accept, and grabs whatever banner
the service sends. Service/product detection is best-effort (parsed from
the banner), so pair it with the ``nmap`` provider or your own tool when
you need accurate version information.

Configuration (environment variables):

``NETWORK_SCAN_PORTS``
    Comma-separated list of ports to probe. Defaults to
    :data:`~Network.providers.base.DEFAULT_SCAN_PORTS`.
``NETWORK_SCAN_TIMEOUT``
    Per-port connect timeout in seconds (default ``1.5``).
``NETWORK_SCAN_WORKERS``
    Number of parallel connections (default ``32``).
"""

from __future__ import annotations

import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from .base import (
    DEFAULT_SCAN_PORTS,
    HostScanResult,
    NetworkScanError,
    NetworkScanProvider,
    ServiceInfo,
)

# Ports where the client is expected to speak first; send a harmless probe
# so the server replies with something we can parse.
_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 9000, 9200, 10000}

_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)[/ ](\d+(?:\.\d+)+)")


def _parse_ports(raw: Optional[str]) -> List[int]:
    if not raw:
        return list(DEFAULT_SCAN_PORTS)
    ports: List[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(ports))


class SocketScanProvider(NetworkScanProvider):
    name = "tcp-connect"
    request_interval_seconds = 0.0

    def __init__(self) -> None:
        self.ports = _parse_ports(os.getenv("NETWORK_SCAN_PORTS"))
        self.timeout = float(os.getenv("NETWORK_SCAN_TIMEOUT", "1.5"))
        self.workers = int(os.getenv("NETWORK_SCAN_WORKERS", "32"))

    # ------------------------------------------------------------------
    def _probe(self, ip: str, port: int, hostname: Optional[str]) -> Optional[ServiceInfo]:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner = b""
                if port in _HTTP_PORTS:
                    host_header = hostname or ip
                    try:
                        sock.sendall(
                            f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\n\r\n".encode()
                        )
                    except OSError:
                        pass
                try:
                    banner = sock.recv(1024)
                except (socket.timeout, OSError):
                    banner = b""
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

        text = banner.decode("utf-8", errors="replace").strip()
        product, version = "Unknown", ""
        # Prefer the HTTP Server header when present.
        m = re.search(r"^Server:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        candidate = m.group(1) if m else text
        pm = _BANNER_RE.search(candidate)
        if pm:
            product, version = pm.group(1), pm.group(2)
        elif candidate and not candidate.startswith("HTTP/"):
            product = candidate.split()[0][:40]
        return ServiceInfo(port=port, product=product, version=version, banner=text)

    # ------------------------------------------------------------------
    def scan_host(self, ip: str, hostname: Optional[str] = None) -> HostScanResult:
        try:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                results = list(pool.map(lambda p: self._probe(ip, p, hostname), self.ports))
        except Exception as exc:  # pragma: no cover - defensive
            raise NetworkScanError(f"TCP connect scan failed for {ip}: {exc}") from exc

        services = [r for r in results if r is not None]
        return HostScanResult(
            ip=ip,
            ports=[s.port for s in services],
            services=services,
        )

"""
Template for plugging in your own network-scanning tool.

Copy this file, rename the class, implement ``scan_host`` and set::

    NETWORK_SCAN_PROVIDER=Network.providers.my_provider:MyProvider

The example below wraps a hypothetical hosted "internet scanning" API that
exposes ``GET /host/<ip>`` and returns JSON like::

    {"ports": [22, 443],
     "services": [{"port": 22, "product": "OpenSSH", "version": "9.4",
                   "banner": "SSH-2.0-OpenSSH_9.4", "cves": ["CVE-2024-6387"]}]}

Adjust the request and the field mapping to match whatever tool you use
(a vendor API, an internal scanner, a database of previous scans...).
"""

from __future__ import annotations

import os
from typing import Optional

import requests

from .base import (
    HostScanResult,
    NetworkScanAuthError,
    NetworkScanError,
    NetworkScanNoDataError,
    NetworkScanProvider,
    ServiceInfo,
)


class ExampleHttpApiProvider(NetworkScanProvider):
    name = "example-http-api"
    # Most hosted scanners enforce a request rate; the scanner sleeps this
    # long between hosts.
    request_interval_seconds = 1.1

    def __init__(self) -> None:
        self.base_url = os.getenv("NETWORK_SCAN_API_URL", "").rstrip("/")
        self.api_key = os.getenv("NETWORK_SCAN_API_KEY", "")
        self.timeout = float(os.getenv("NETWORK_SCAN_API_TIMEOUT", "30"))

    def validate_config(self) -> None:
        if not self.base_url:
            raise NetworkScanError("NETWORK_SCAN_API_URL is not set")
        if not self.api_key:
            raise NetworkScanAuthError("NETWORK_SCAN_API_KEY is not set")

    def scan_host(self, ip: str, hostname: Optional[str] = None) -> HostScanResult:
        try:
            resp = requests.get(
                f"{self.base_url}/host/{ip}",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise NetworkScanError(f"request failed: {exc}") from exc

        if resp.status_code == 401:
            raise NetworkScanAuthError("invalid API key")
        if resp.status_code == 404:
            raise NetworkScanNoDataError(f"no data for {ip}")
        if resp.status_code == 429:
            raise NetworkScanError("rate limit exceeded")
        if resp.status_code != 200:
            raise NetworkScanError(f"unexpected status {resp.status_code}")

        try:
            payload = resp.json()
        except ValueError as exc:
            raise NetworkScanError("response was not valid JSON") from exc

        services = [
            ServiceInfo(
                port=int(item["port"]),
                product=item.get("product") or "Unknown",
                version=item.get("version") or "",
                banner=item.get("banner") or "",
                vulns=list(item.get("cves") or []),
            )
            for item in payload.get("services", [])
        ]
        ports = list(payload.get("ports") or [s.port for s in services])
        return HostScanResult(ip=ip, ports=ports, services=services, raw=payload)

"""
Base contract for network-scanning providers.

A provider answers one question: *what is listening on this host?*
Everything else (severity mapping, scoring, persistence) is handled by the
network scanner, so a provider only has to return open ports and whatever
service details it can gather.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Ports the built-in providers probe when nothing else is configured.
# These match the severity table in Network/network_scanner_api.py plus a
# few common management/web ports.
DEFAULT_SCAN_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465,
    587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389,
    5000, 5432, 5900, 5984, 6379, 7001, 8000, 8080, 8443, 8888, 9000,
    9200, 9300, 10000, 11211, 27017,
]


class NetworkScanError(Exception):
    """Generic provider failure (timeouts, malformed responses, tool crashed).

    Raising this triggers an external-API failure alert in the dashboard.
    """


class NetworkScanAuthError(NetworkScanError):
    """The provider rejected our credentials (missing/invalid API key)."""


class NetworkScanNoDataError(NetworkScanError):
    """The provider has no information about this host.

    This is *not* treated as a failure: the host is simply recorded with
    no open ports and no alert is raised.
    """


@dataclass
class ServiceInfo:
    """One listening service on a host."""

    port: int
    transport: str = "tcp"
    product: str = "Unknown"
    version: str = ""
    banner: str = ""
    # CVE identifiers the provider associates with this service, if any.
    vulns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "transport": self.transport,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "vulns": list(self.vulns),
        }


@dataclass
class HostScanResult:
    """Normalised result returned by every provider."""

    ip: str
    ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    # Optional provider-specific payload, kept for debugging only.
    raw: Optional[Any] = None

    def service_for_port(self, port: int) -> Optional[ServiceInfo]:
        for svc in self.services:
            if svc.port == port:
                return svc
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "ports": list(self.ports),
            "services": [s.to_dict() for s in self.services],
        }


class NetworkScanProvider(ABC):
    """Interface every network-scanning backend must implement.

    Subclass this, implement :meth:`scan_host`, and point
    ``NETWORK_SCAN_PROVIDER`` at your class (``my_pkg.my_module:MyProvider``).
    """

    #: Human-readable name used in logs and failure alerts.
    name: str = "network-scanner"

    #: Minimum pause between two consecutive ``scan_host`` calls. Use this
    #: to respect the rate limit of an external API. ``0`` disables it.
    request_interval_seconds: float = 0.0

    def validate_config(self) -> None:
        """Raise :class:`NetworkScanAuthError` / :class:`NetworkScanError`
        if the provider is not usable (missing API key, binary not found...).

        Called once before a scan starts. The default implementation does
        nothing.
        """

    @abstractmethod
    def scan_host(self, ip: str, hostname: Optional[str] = None) -> HostScanResult:
        """Return the open ports and services for ``ip``.

        ``hostname`` is the subdomain that resolved to ``ip``; providers that
        work on names rather than addresses can use it.

        Must raise :class:`NetworkScanNoDataError` when the host is unknown
        to the provider, :class:`NetworkScanAuthError` on credential
        problems and :class:`NetworkScanError` for anything else.
        """

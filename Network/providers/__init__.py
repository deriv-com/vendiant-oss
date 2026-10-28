"""
Pluggable network-scanning providers.

The network scanner (``Network/network_scanner_api.py``) never talks to a
scanning tool directly. It asks :func:`get_provider` for an object that
implements :class:`NetworkScanProvider` and calls ``scan_host`` on it.

Which provider is used is decided by the ``NETWORK_SCAN_PROVIDER``
environment variable:

``socket`` (default)
    Built-in TCP connect scan with banner grabbing. No external
    dependencies, no API key. Scans the ports listed in
    ``NETWORK_SCAN_PORTS`` (defaults to :data:`DEFAULT_SCAN_PORTS`).

``nmap``
    Wraps a locally installed ``nmap`` binary (service/version detection).

``<module.path>:<ClassName>``
    Any importable class that subclasses :class:`NetworkScanProvider`.
    Use this to drop in your own tool or a commercial internet-scanning
    API. See ``custom_provider_example.py`` and ``docs/NETWORK_SCANNING.md``.
"""

from .base import (
    DEFAULT_SCAN_PORTS,
    HostScanResult,
    NetworkScanAuthError,
    NetworkScanError,
    NetworkScanNoDataError,
    NetworkScanProvider,
    ServiceInfo,
)
from .loader import get_provider, list_builtin_providers

__all__ = [
    "DEFAULT_SCAN_PORTS",
    "HostScanResult",
    "NetworkScanAuthError",
    "NetworkScanError",
    "NetworkScanNoDataError",
    "NetworkScanProvider",
    "ServiceInfo",
    "get_provider",
    "list_builtin_providers",
]

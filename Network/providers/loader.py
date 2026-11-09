"""Resolve the configured :class:`NetworkScanProvider`."""

from __future__ import annotations

import importlib
import os
from typing import Dict, Optional, Type

from .base import NetworkScanError, NetworkScanProvider

# Built-in providers, addressed relative to this package so they resolve
# whether the package is imported as ``Network.providers`` (repo root on
# sys.path) or as ``providers`` (the dashboard adds ``Network/`` to sys.path).
_BUILTIN: Dict[str, str] = {
    "socket": ".socket_provider:SocketScanProvider",
    "tcp": ".socket_provider:SocketScanProvider",
    "nmap": ".nmap_provider:NmapScanProvider",
}

DEFAULT_PROVIDER = "socket"


def list_builtin_providers() -> Dict[str, str]:
    """Names accepted by ``NETWORK_SCAN_PROVIDER`` and the class each maps to."""
    return {k: f"{__package__}{v}" for k, v in _BUILTIN.items()}


def _looks_like_provider(cls: object) -> bool:
    if not isinstance(cls, type):
        return False
    if issubclass(cls, NetworkScanProvider):
        return True
    # Same class imported under a different package name (``Network.providers``
    # vs ``providers``) is not a subclass by identity; accept it structurally.
    return callable(getattr(cls, "scan_host", None))


def _import_class(spec: str) -> Type[NetworkScanProvider]:
    if ":" not in spec:
        raise NetworkScanError(
            f"Invalid NETWORK_SCAN_PROVIDER '{spec}'. Use a built-in name "
            f"({', '.join(sorted(_BUILTIN))}) or 'module.path:ClassName'."
        )
    module_path, class_name = spec.split(":", 1)
    try:
        if module_path.startswith("."):
            module = importlib.import_module(module_path, package=__package__)
        else:
            module = importlib.import_module(module_path)
    except ImportError as exc:
        raise NetworkScanError(
            f"could not import provider module '{module_path}': {exc}"
        ) from exc
    cls = getattr(module, class_name, None)
    if not _looks_like_provider(cls):
        raise NetworkScanError(f"{spec} is not a NetworkScanProvider subclass")
    return cls  # type: ignore[return-value]


def get_provider(spec: Optional[str] = None) -> NetworkScanProvider:
    """Instantiate the provider named by ``spec`` or ``NETWORK_SCAN_PROVIDER``."""
    spec = (spec or os.getenv("NETWORK_SCAN_PROVIDER") or DEFAULT_PROVIDER).strip()
    target = _BUILTIN.get(spec.lower(), spec)
    return _import_class(target)()

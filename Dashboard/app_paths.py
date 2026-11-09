"""Central path resolution for the Vendiant backend (local dev + container)."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_app_root() -> Path:
    """Return the repository root (/app in the container, project root locally)."""
    env_root = os.environ.get("VENDIANT_APP_ROOT", "").strip()
    if env_root:
        return Path(env_root).resolve()

    try:
        return Path(__file__).resolve().parent.parent
    except NameError:
        return Path("/app")


def app_join(*parts: str) -> str:
    return str(get_app_root().joinpath(*parts))

"""Shared device-state cleanup used during unlink and re-enrollment."""

from __future__ import annotations

import glob
import logging
import os

logger = logging.getLogger("agent.state_cleanup")


def clear_device_state(state_dir: str) -> None:
    """Remove credentials, queues, inventory cache, and SQLite sidecars."""
    os.makedirs(state_dir, exist_ok=True)
    names = {
        "zerowatch_token.dat", "zw_offline_queue.dat", "zw_team_join_state.dat",
        "consent_accepted.dat", "device_fingerprint.json", "products.csv",
        "dashboard_cache.dat", "asset_info.json", "unlink.signal",
        "shutdown.signal", "sentinel_agent.log",
        "agent_token.enc", "join_state.json",
    }
    paths = [os.path.join(state_dir, name) for name in names]
    paths.extend(glob.glob(os.path.join(state_dir, "scan_cache.db*")))
    for path in set(paths):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError as exc:
            logger.warning("Unable to remove device state %s: %s", path, exc)

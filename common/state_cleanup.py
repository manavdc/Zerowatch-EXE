"""Shared device-state cleanup used during unlink and re-enrollment."""

from __future__ import annotations

import logging
import os
import shutil

logger = logging.getLogger("agent.state_cleanup")


def clear_device_state(state_dir: str) -> None:
    """Wipe every entry in the device state directory, retaining the directory."""
    os.makedirs(state_dir, exist_ok=True)
    for name in os.listdir(state_dir):
        path = os.path.join(state_dir, name)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                try:
                    os.chmod(path, 0o666)
                except OSError:
                    pass
                os.remove(path)
        except OSError as exc:
            logger.warning("Unable to remove device state %s: %s", path, exc)

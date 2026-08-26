"""OTA coordinator for headless Linux and macOS agents."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
from typing import Optional

from common import updater

logger = logging.getLogger("ota.daemon")


class DaemonOTAMonitor:
    def __init__(self, current_exe: str, current_version: str,
                 shutdown_event: Optional[threading.Event] = None) -> None:
        self.current_exe = os.path.abspath(current_exe)
        self.shutdown_event = shutdown_event or threading.Event()
        self._monitor = updater.BackgroundUpdateMonitor(
            current_version=current_version,
            on_update_available=self._apply_update,
        )

    def start(self) -> None:
        self._monitor.start()

    def stop(self) -> None:
        self._monitor.stop()

    def _apply_update(self, info: updater.UpdateInfo) -> None:
        tmp_dir = tempfile.mkdtemp(prefix="zerowatch_ota_")
        dest = os.path.join(tmp_dir, info.target.filename)
        try:
            logger.info("[OTA] Applying v%s for %s", info.version, info.platform_key)
            updater.BinaryDownloader().download(info.target, dest)
            from common.os_replacer import perform_update
            if perform_update(dest, self.current_exe):
                if os.name == "nt":
                    from common.os_replacer import _relaunch_detached
                    if not _relaunch_detached(self.current_exe):
                        raise RuntimeError("Windows replacement process could not be launched")
                logger.info("[OTA] Update applied; supervisor restart requested.")
                self.shutdown_event.set()
        except Exception as exc:
            logger.error("[OTA] Headless update failed: %s", exc, exc_info=True)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def start_daemon_ota_monitor(current_exe: str, current_version: str,
                             shutdown_event: threading.Event) -> DaemonOTAMonitor:
    monitor = DaemonOTAMonitor(current_exe, current_version, shutdown_event)
    monitor.start()
    return monitor

"""
linux/scanner/file_watcher.py
─────────────────────────────────────────────────────────────────────────────
Linux implementation of FileWatcher interface.

Architecture:
  inotify events → Event Queue → Debounce (5s) → Relevant filter → callback

Uses inotify_simple if available (soft dependency).
Falls back to polling (os.stat-based) if inotify is unavailable.

inotify Watch limits:
  - Only PRIORITY_DIRS are watched, not the entire filesystem.
  - /proc/sys/fs/inotify/max_user_watches typically limits to 8192–65536.
  - Monitoring 10–20 directories stays well within any system default.

Debouncing:
  - 200 rapid events (e.g. npm install) produce ONE incremental scan,
    not 200 backend synchronizations.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from common.scanner.interfaces import FileWatcher
from linux.scanner.fs_walker import PRIORITY_DIRS, EntryKind
from common.scanner.fs_constants import MANIFEST_FILENAMES, MAX_BINARY_SIZE_BYTES

logger = logging.getLogger("linux.scanner.file_watcher")

_DEBOUNCE_SECONDS = 5.0   # Collect events for 5s before triggering a scan
_POLL_INTERVAL   = 60     # Polling fallback: check every 60s


# ── inotify backend ───────────────────────────────────────────────────────────

def _try_import_inotify():
    try:
        import inotify_simple
        return inotify_simple
    except ImportError:
        return None


# ── File relevance filter ─────────────────────────────────────────────────────

def _is_relevant(path: str) -> bool:
    """Return True if this path is worth triggering an incremental scan."""
    name = os.path.basename(path)
    if name in MANIFEST_FILENAMES or name.lower() in MANIFEST_FILENAMES:
        return True
    # ELF executables and shared libraries
    lower = name.lower()
    if lower.endswith(".so") or ".so." in lower:
        return True
    # Executable bit (checked lazily here)
    try:
        st = os.stat(path)
        if st.st_mode & 0o111 and 0 < st.st_size <= MAX_BINARY_SIZE_BYTES:
            return True
    except OSError:
        pass
    return False


# ── inotify-based watcher ─────────────────────────────────────────────────────

class _InotifyWatcher:
    """Background inotify watcher with debounce."""

    IN_CLOSE_WRITE = 0x00000008
    IN_MOVED_TO    = 0x00000080
    IN_CREATE      = 0x00000100
    IN_DELETE      = 0x00000200
    IN_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE

    def __init__(self, watch_dirs: List[str], callback: Callable):
        self._callback = callback
        self._watch_dirs = watch_dirs
        self._stop = threading.Event()
        self._event_queue: "queue.Queue[str]" = queue.Queue()
        self._thread = threading.Thread(
            target=self._run, name="linux-inotify", daemon=True
        )
        self._debounce_thread = threading.Thread(
            target=self._debouncer, name="linux-inotify-debounce", daemon=True
        )

    def start(self):
        self._thread.start()
        self._debounce_thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        inotify_simple = _try_import_inotify()
        if inotify_simple is None:
            logger.warning("inotify_simple not available — inotify watcher inactive")
            return
        try:
            inotify = inotify_simple.INotify()
            wd_to_path: Dict[int, str] = {}
            for d in self._watch_dirs:
                if os.path.isdir(d):
                    try:
                        wd = inotify.add_watch(d, self.IN_MASK)
                        wd_to_path[wd] = d
                        logger.debug("inotify watching: %s", d)
                    except OSError as exc:
                        logger.debug("Cannot watch %s: %s", d, exc)

            while not self._stop.is_set():
                events = inotify.read(timeout=1000)
                for event in events:
                    dirpath = wd_to_path.get(event.wd, "")
                    if not dirpath or not event.name:
                        continue
                    full_path = os.path.join(dirpath, event.name)
                    self._event_queue.put(full_path)
        except Exception as exc:
            logger.warning("inotify watcher crashed: %s", exc)

    def _debouncer(self):
        """Drain event queue every DEBOUNCE_SECONDS and fire callback once."""
        pending: Set[str] = set()
        while not self._stop.is_set():
            try:
                path = self._event_queue.get(timeout=_DEBOUNCE_SECONDS)
                pending.add(path)
                # Drain remaining quickly-queued events
                while True:
                    try:
                        pending.add(self._event_queue.get_nowait())
                    except queue.Empty:
                        break
                # Now wait for quiescence
                time.sleep(_DEBOUNCE_SECONDS)
                while True:
                    try:
                        pending.add(self._event_queue.get_nowait())
                    except queue.Empty:
                        break
                relevant = [p for p in pending if _is_relevant(p)]
                if relevant:
                    logger.info("inotify: %d relevant file changes detected", len(relevant))
                    try:
                        self._callback(relevant, [])
                    except Exception as exc:
                        logger.warning("File watcher callback error: %s", exc)
                pending.clear()
            except queue.Empty:
                pass


# ── Polling fallback ──────────────────────────────────────────────────────────

class _PollingWatcher:
    """Simple polling watcher — used when inotify_simple is not installed."""

    def __init__(self, watch_dirs: List[str], callback: Callable):
        self._callback = callback
        self._watch_dirs = watch_dirs
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="linux-poll-watcher", daemon=True
        )
        self._snapshots: Dict[str, int] = {}  # path → mtime_ns

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _snapshot(self) -> Dict[str, int]:
        snap: Dict[str, int] = {}
        for d in self._watch_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.scandir(d):
                    if entry.is_file(follow_symlinks=False):
                        try:
                            snap[entry.path] = entry.stat(follow_symlinks=False).st_mtime_ns
                        except OSError:
                            pass
            except OSError:
                pass
        return snap

    def _run(self):
        self._snapshots = self._snapshot()
        while not self._stop.is_set():
            time.sleep(_POLL_INTERVAL)
            new_snap = self._snapshot()
            changed = [
                p for p, mtime in new_snap.items()
                if p not in self._snapshots or self._snapshots[p] != mtime
            ]
            deleted = [p for p in self._snapshots if p not in new_snap]
            self._snapshots = new_snap

            relevant_changed = [p for p in changed if _is_relevant(p)]
            if relevant_changed or deleted:
                logger.info(
                    "Polling: %d changed, %d deleted relevant files",
                    len(relevant_changed), len(deleted)
                )
                try:
                    self._callback(relevant_changed, deleted)
                except Exception as exc:
                    logger.warning("File watcher callback error: %s", exc)


# ── LinuxFileWatcher (public interface) ───────────────────────────────────────

class LinuxFileWatcher(FileWatcher):
    """
    Linux implementation of FileWatcher.
    Uses inotify_simple if available, falls back to polling.
    Watches PRIORITY_DIRS only — not millions of directories.
    """

    def __init__(self, extra_dirs: Optional[List[str]] = None):
        self._extra_dirs = extra_dirs or []
        self._watcher: Optional[_InotifyWatcher | _PollingWatcher] = None

    def start_monitoring(
        self,
        interval: int,
        callback: Callable[[List[dict], List[dict]], None],
    ) -> None:
        watch_dirs = [d for d in PRIORITY_DIRS if os.path.isdir(d)] + self._extra_dirs

        if _try_import_inotify() is not None:
            logger.info("LinuxFileWatcher: using inotify backend")
            self._watcher = _InotifyWatcher(watch_dirs, callback)
        else:
            logger.info("LinuxFileWatcher: inotify_simple unavailable — using polling fallback")
            self._watcher = _PollingWatcher(watch_dirs, callback)

        self._watcher.start()

    def stop_monitoring(self) -> None:
        if self._watcher is not None:
            self._watcher.stop()
            self._watcher = None

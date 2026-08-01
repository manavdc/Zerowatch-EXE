"""
scanner/orchestrator.py
─────────────────────────────────────────────────────────────────────────────
Scan orchestrator: coordinates all layers, manages the cache, and
produces a unified inventory in the format consumed by ZeroWatchClient.

USAGE IN sentinel_agent.py
───────────────────────────
    from scanner import ScanOrchestrator

    # Once at startup, create the orchestrator (pass the existing
    # get_installed_software_registry function so Layer 0 can call it)
    orchestrator = ScanOrchestrator(
        base_dir=base_dir,
        existing_registry_fn=get_installed_software_registry,
        agent_version=AGENT_VERSION,
    )

    # Replace the existing full scan call:
    # BEFORE: software = get_installed_software_registry()
    # AFTER:
    software = orchestrator.run_full_scan()          # → list[dict]

    # Replace the monitor loop's registry call:
    # BEFORE: current_list = get_installed_software_registry()
    # AFTER:
    added, removed = orchestrator.run_delta_scan()  # → (list[dict], list[dict])

    # Both return the exact dict shape that sync_full / sync_delta expect.

CONCURRENCY MODEL
─────────────────
• Layer 0 (registry) runs synchronously on the calling thread.
  Registry access is fast (<500 ms) and the results are needed
  immediately for the initial sync.

• Layer 1 (PE binaries) and Layer 2 (manifests) run in a
  ThreadPoolExecutor with max_workers=4.
  - Filesystem I/O releases the GIL, so Python threads are genuinely
    parallel for these workloads.
  - 4 workers saturates a typical SSD without over-committing CPU.

• The orchestrator yields a batch of API-ready dicts as each layer
  completes rather than waiting for the entire scan.  This means the
  caller can submit a partial sync immediately after Layer 0 finishes
  (fast, authoritative data) and then submit another sync when
  Layers 1+2 complete.

INCREMENTAL SCANNING (DELTA MODE)
──────────────────────────────────
The first call to run_full_scan() sets the "last known inventory" as
the full result.  Subsequent calls to run_delta_scan() compare the
new scan against that snapshot and return only (added, removed).

The snapshot is backed by the SQLite cache so it survives agent restarts.

DEDUPLICATION STRATEGY
───────────────────────
Items from multiple layers may refer to the same component:
  - Registry discovers "OpenSSL 3.1.2"
  - Layer 1 PE-inspects libssl-3.dll and finds "OpenSSL 3.1.2"
  - A Conan lockfile also lists "openssl:3.1.2"

All three are collapsed into one item using the dedup_key():
  f"{name.lower()}::{version.lower()}"

Higher-priority sources win:
  Layer 0 (registry) > Layer 0 (driver) > Layer 1 (PE) > Layer 2 (manifest)

BACKGROUND SCAN OPTION
───────────────────────
run_background_scan() fires the filesystem scan in a daemon thread and
calls a callback when each batch of results arrives.  Used by the
daemon's heartbeat loop so that background scanning does not block
the heartbeat or registry monitor.
"""

from __future__ import annotations

import datetime
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple

from .fs_walker import (
    EntryKind,
    walk_specified_dirs,
    get_priority_scan_dirs,
    BINARY_EXTENSIONS,
)
from .layer2_manifests import parse_manifest_file
from .models import SoftwareItem, SOURCE_REGISTRY
from .state_cache import ScanCache
from common.scanner.interfaces import (
    SoftwareCollector,
    BinaryInspector,
    FilesystemWalker,
)

logger = logging.getLogger("scanner.orchestrator")


# ── Source priority for dedup (lower number = higher priority) ────────────────

_SOURCE_PRIORITY: Dict[str, int] = {
    "registry":         0,
    "os":               0,
    "driver":           1,
    "windows_store":    1,
    "pe_binary":        2,
    "pe_dll":           2,
    "pe_sys":           1,
    "jar_manifest":     3,
    "npm_manifest":     4,
    "npm_lockfile":     4,
    "pip_requirements": 4,
    "pip_lockfile":     4,
    "pyproject":        4,
    "maven":            4,
    "gradle":           4,
    "nuget":            4,
    "go_mod":           4,
    "cargo":            4,
    "gem":              4,
    "composer":         4,
    "zip_archive":      5,
}

_DEFAULT_PRIORITY = 9

# ── Worker batch size for thread pool tasks ────────────────────────────────────

_BINARY_BATCH_SIZE  = 50   # binaries per worker task
_MANIFEST_BATCH_SIZE = 20   # manifests per worker task


# ── Orchestrator ──────────────────────────────────────────────────────────────

class ScanOrchestrator:
    """
    Central coordinator for all scanner layers.
    Receives scanner implementations via constructor injection.

    Parameters
    ──────────
    base_dir
        The agent's base directory (where state files are stored).

    existing_registry_fn
        # TODO: Remove after Windows migration completes.
        Legacy registry callable for backward compatibility.

    agent_version
        Used to invalidate the cache when the agent is updated.

    max_workers
        Thread pool size for Layer 1/2 I/O workers. Default 4.

    extra_scan_dirs
        Optional additional directories to include in every filesystem scan.

    fs_scan_interval_hours
        How often the priority-path incremental scan runs. Default 4 hours.

    deep_scan_interval_hours
        How often the full drive walk runs. Default 24 hours.

    software_collector
        Injected implementation of SoftwareCollector interface.

    binary_inspector
        Injected implementation of BinaryInspector interface.

    filesystem_walker
        Injected implementation of FilesystemWalker interface.
    """

    def __init__(
        self,
        base_dir: str,
        existing_registry_fn: Optional[Callable[[], List[dict]]] = None,  # TODO: Remove after Windows migration completes.
        agent_version: str = "unknown",
        max_workers: int = 4,
        extra_scan_dirs: Optional[List[str]] = None,
        fs_scan_interval_hours: float = 4.0,
        deep_scan_interval_hours: float = 24.0,
        software_collector: Optional[SoftwareCollector] = None,
        binary_inspector: Optional[BinaryInspector] = None,
        filesystem_walker: Optional[FilesystemWalker] = None,
    ):
        self._base_dir = base_dir
        self._registry_fn = existing_registry_fn  # TODO: Remove after Windows migration completes.
        self._agent_version = agent_version
        self._max_workers = max_workers
        self._extra_dirs = extra_scan_dirs or []

        # Fallback adapter resolution for legacy constructor invocations
        if software_collector is None or binary_inspector is None or filesystem_walker is None:
            from .adapters import create_default_windows_collectors
            reg_fn = existing_registry_fn or (lambda: [])
            def_sw, def_bin, def_fs = create_default_windows_collectors(reg_fn)
            software_collector = software_collector or def_sw
            binary_inspector = binary_inspector or def_bin
            filesystem_walker = filesystem_walker or def_fs

        # Interface validation against ABCs
        if not isinstance(software_collector, SoftwareCollector):
            raise TypeError(f"software_collector must implement SoftwareCollector, got {type(software_collector).__name__}")
        if not isinstance(binary_inspector, BinaryInspector):
            raise TypeError(f"binary_inspector must implement BinaryInspector, got {type(binary_inspector).__name__}")
        if not isinstance(filesystem_walker, FilesystemWalker):
            raise TypeError(f"filesystem_walker must implement FilesystemWalker, got {type(filesystem_walker).__name__}")

        self._software_collector = software_collector
        self._binary_inspector = binary_inspector
        self._filesystem_walker = filesystem_walker

        # ── Scan interval configuration ────────────────────────────────────
        self._fs_scan_interval   = fs_scan_interval_hours * 3600
        self._deep_scan_interval = deep_scan_interval_hours * 3600

        # ── Persistent cache ───────────────────────────────────────────────
        state_dir = self._state_dir()
        os.makedirs(state_dir, exist_ok=True)
        self._cache = ScanCache(
            db_path=os.path.join(state_dir, "scan_cache.db"),
            agent_version=agent_version,
        )

        # ── Last known inventory snapshot (for delta computation) ──────────
        self._snapshot_lock = threading.Lock()
        self._last_snapshot: Dict[str, SoftwareItem] = {}

        # ── Periodic scan thread state ─────────────────────────────────────
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_stop = threading.Event()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _state_dir(self) -> str:
        """Returns the path to the agent's state directory."""
        # Mirrors the existing _secure_state_dir() / _state_path() logic
        # from sentinel_agent.py without importing it.
        candidates = [
            os.path.join(os.environ.get("PROGRAMDATA", ""), "ZeroWatch", "state"),
            os.path.join(self._base_dir, "state"),
        ]
        for c in candidates:
            try:
                os.makedirs(c, exist_ok=True)
                # Quick write test
                test = os.path.join(c, ".write_test")
                with open(test, "w") as fh:
                    fh.write("x")
                os.remove(test)
                return c
            except OSError:
                pass
        return os.path.join(self._base_dir, "state")

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0
        ).isoformat()

    # ── Deduplication ─────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate(items: List[SoftwareItem]) -> List[SoftwareItem]:
        """
        Collapse duplicate items by dedup_key().
        When two items share the same key, keep the one with the higher
        priority source (lower _SOURCE_PRIORITY value).
        """
        best: Dict[str, SoftwareItem] = {}
        for item in items:
            if not item.is_valid():
                continue
            key = item.dedup_key()
            if key not in best:
                best[key] = item
            else:
                existing = best[key]
                existing_prio = _SOURCE_PRIORITY.get(existing.source, _DEFAULT_PRIORITY)
                new_prio      = _SOURCE_PRIORITY.get(item.source,    _DEFAULT_PRIORITY)
                if new_prio < existing_prio:
                    best[key] = item
        return list(best.values())

    # ── Layer 0 scan (synchronous, fast) ──────────────────────────────────────

    def _run_layer0(self) -> List[SoftwareItem]:
        """
        Run all Layer 0 scanners synchronously via the injected software_collector interface.
        Returns combined list of SoftwareItems.
        """
        items = self._software_collector.collect_software()
        logger.info("Layer 0 complete: %d items", len(items))
        return items

    # ── Layer 1/2 scan (threaded, filesystem) ─────────────────────────────────

    def _run_filesystem_scan(
        self,
        stop_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> List[SoftwareItem]:
        """
        Walk all local fixed drives and process binaries + manifests.
        Uses ThreadPoolExecutor for parallel processing.

        Parameters
        ──────────
        stop_event
            If set and signalled, the scan aborts gracefully after the
            current batch.

        progress_callback
            Called periodically with a count of processed files.
        """
        items: List[SoftwareItem] = []

        binary_batch:   List[str] = []
        manifest_batch: List[str] = []

        processed = 0
        futures = []

        with ThreadPoolExecutor(max_workers=self._max_workers, thread_name_prefix="scanner") as pool:

            def flush_binaries() -> None:
                if binary_batch:
                    batch_copy = list(binary_batch)
                    binary_batch.clear()
                    futures.append(
                        pool.submit(
                            _process_binary_batch, batch_copy, self._cache, self._binary_inspector
                        )
                    )

            def flush_manifests() -> None:
                if manifest_batch:
                    batch_copy = list(manifest_batch)
                    manifest_batch.clear()
                    futures.append(
                        pool.submit(
                            _process_manifest_batch, batch_copy, self._cache
                        )
                    )

            for path, kind in self._filesystem_walker.walk_filesystem(extra_dirs=self._extra_dirs):
                if stop_event and stop_event.is_set():
                    logger.info("Filesystem scan aborted by stop event.")
                    break

                processed += 1
                if progress_callback and processed % 500 == 0:
                    progress_callback(processed)

                if kind == EntryKind.MANIFEST:
                    manifest_batch.append(path)
                    if len(manifest_batch) >= _MANIFEST_BATCH_SIZE:
                        flush_manifests()
                else:  # BINARY
                    binary_batch.append(path)
                    if len(binary_batch) >= _BINARY_BATCH_SIZE:
                        flush_binaries()

            # Flush remaining
            flush_binaries()
            flush_manifests()

            # Collect results
            for future in as_completed(futures):
                try:
                    items.extend(future.result())
                except Exception as exc:
                    logger.warning("Worker task failed: %s", exc)

        logger.info(
            "Filesystem scan complete: %d files processed, %d items found",
            processed, len(items)
        )
        return items

    # ── Public API ────────────────────────────────────────────────────────────

    def run_full_scan(
        self,
        include_filesystem: bool = True,
        stop_event: Optional[threading.Event] = None,
    ) -> List[dict]:
        """
        Run all layers and return the unified inventory as a list of dicts
        ready for ZeroWatchClient.sync_full().

        Parameters
        ──────────
        include_filesystem
            If False, runs only Layer 0 (registry-based scans).  Used
            for the initial startup sync so the first heartbeat is fast.

        stop_event
            Optional shutdown signal to abort the filesystem scan.

        Returns
        ───────
        List of dicts in the format expected by sync_full():
            [{name, version, vendor, source, category, install_date, ...}]
        """
        t0 = time.perf_counter()

        # Check if this is a cold start (no filesystem scan has run yet)
        is_cold = not bool(self._cache.get_meta("last_fs_scan_at"))
        if is_cold:
            logger.info("Cold start detected: forcing full filesystem scan for complete inventory.")
            include_filesystem = True

        # ── Layer 0 (always synchronous) ───────────────────────────────────
        items = self._run_layer0()

        # ── Layers 1 + 2 (filesystem, threaded) ───────────────────────────
        if include_filesystem:
            fs_new, _fs_removed = self._run_full_drive_scan(stop_event=stop_event)
            items.extend(fs_new)
            # Mark filesystem scan as completed in cache
            if not (stop_event and stop_event.is_set()):
                self._cache.set_meta("last_fs_scan_at", self._utc_now_iso())
        else:
            # On warm start, merge cached filesystem items with Layer 0 registry items
            # so the full sync payload is complete and doesn't wipe them from the server.
            cached_items = self._cache.all_cached_items()
            items.extend(cached_items)

        # ── Deduplicate ────────────────────────────────────────────────────
        unique = self._deduplicate(items)

        elapsed = time.perf_counter() - t0
        logger.info(
            "Full scan complete: %d unique items in %.1f s", len(unique), elapsed
        )

        # ── Update snapshot for next delta computation ─────────────────────
        with self._snapshot_lock:
            if include_filesystem:
                self._last_snapshot = {item.dedup_key(): item for item in unique}
            else:
                for item in unique:
                    self._last_snapshot[item.dedup_key()] = item

        # ── Update cache meta ──────────────────────────────────────────────
        self._cache.set_meta("last_full_scan_at", self._utc_now_iso())

        return [item.to_api_dict() for item in unique]

    def run_delta_scan(self) -> Tuple[List[dict], List[dict]]:
        """
        Run all layers and compute (added, removed) against the last snapshot.
        Returns two lists of dicts ready for ZeroWatchClient.sync_delta().

        If no prior snapshot exists, runs a full scan and returns
        (all_items, []).
        """
        with self._snapshot_lock:
            if not self._last_snapshot:
                # First run — treat everything as new
                all_items = self.run_full_scan()
                return all_items, []

        # Rescan
        items = self._run_layer0()
        fs_items = self._run_filesystem_scan()
        items.extend(fs_items)
        unique = self._deduplicate(items)
        new_snapshot = {item.dedup_key(): item for item in unique}

        with self._snapshot_lock:
            old_keys = set(self._last_snapshot.keys())
            new_keys = set(new_snapshot.keys())

            added_keys   = new_keys - old_keys
            removed_keys = old_keys - new_keys

            added_items   = [new_snapshot[k].to_api_dict() for k in added_keys]
            removed_items = [self._last_snapshot[k].to_api_dict() for k in removed_keys]

            # Tag change type
            for d in added_items:
                d["change_type"] = "added"
            for d in removed_items:
                d["change_type"] = "removed"

            self._last_snapshot = new_snapshot

        logger.info(
            "Delta scan: +%d added, -%d removed", len(added_items), len(removed_items)
        )
        return added_items, removed_items

    def run_registry_delta(self) -> Tuple[List[dict], List[dict]]:
        """
        Fast delta: Layer 0 only (registry + store + drivers).
        Called by monitor_system_changes() every 60s.

        The filesystem scan runs on its own schedule via
        start_periodic_scans() and updates the snapshot independently.
        """
        items = self._run_layer0()
        unique = self._deduplicate(items)
        new_snapshot_l0 = {item.dedup_key(): item for item in unique}

        with self._snapshot_lock:
            old_keys = set(self._last_snapshot.keys())
            new_keys = set(new_snapshot_l0.keys())

            # Only delta on registry-sourced keys to avoid false removals
            # from filesystem items not present in the Layer 0 subset
            l0_sources = {
                "registry", "windows_store", "driver", "os"
            }
            old_l0_keys = {
                k for k, v in self._last_snapshot.items()
                if v.source in l0_sources
            }

            added_keys   = new_keys - old_l0_keys
            removed_keys = old_l0_keys - new_keys

            added   = [new_snapshot_l0[k].to_api_dict() for k in added_keys]
            removed = [self._last_snapshot[k].to_api_dict() for k in removed_keys]

            for d in added:
                d["change_type"] = "added"
            for d in removed:
                d["change_type"] = "removed"

            # Merge the new L0 items into the snapshot, keeping L1/L2 items
            for key, item in new_snapshot_l0.items():
                self._last_snapshot[key] = item

        return added, removed

    # ── Phase 3: Incremental filesystem scanning ───────────────────────────────

    def _run_incremental_scan(
        self,
        scan_dirs: List[str],
        stop_event: Optional[threading.Event] = None,
        label: str = "incremental",
    ) -> Tuple[List[SoftwareItem], List[SoftwareItem]]:
        """
        Core incremental filesystem scan.

        WHAT THE CACHE ELIMINATES
        ─────────────────────────
        The cache eliminates file *parsing* for unchanged files — it does
        NOT eliminate directory traversal.  We still walk every directory
        in scan_dirs to discover files that were created since the last
        scan and have never been seen before.  For each candidate file
        (matching a manifest filename or binary extension), we stat() it
        and compare mtime_ns + size_bytes against the in-memory cache dict.
        If they match, we skip opening and parsing the file entirely.
        Only new or modified files are opened and sent to the thread pool.

        DELETION DETECTION
        ──────────────────
        Any path that was in the cache under one of our scan_dirs but was
        NOT encountered during this walk is assumed to have been deleted.
        Its last-known items are loaded from the cache and returned as
        removed_items so the caller can emit sync_delta removals.

        Parameters
        ──────────
        scan_dirs
            The list of root directories to traverse.  Use
            get_priority_scan_dirs() for periodic scans or
            walk_drives() roots for the daily deep scan.

        stop_event
            If set and signalled, the scan aborts after the current batch.

        label
            String used in log messages to distinguish priority vs deep scans.

        Returns
        ───────
        (new_or_changed_items, removed_items)
        """
        t0 = time.perf_counter()

        # ── Load all cached stats in one SQL query (O(1) per-file lookups) ──
        cached_stats: Dict[str, tuple] = self._cache.all_cached_stats()
        seen_paths: Set[str] = set()

        new_items: List[SoftwareItem] = []
        binary_batch:   List[str] = []
        manifest_batch: List[str] = []
        futures = []

        with ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="scanner"
        ) as pool:

            def _flush_binaries() -> None:
                if binary_batch:
                    batch = list(binary_batch)
                    binary_batch.clear()
                    futures.append(
                        pool.submit(_process_binary_batch, batch, self._cache, self._binary_inspector)
                    )

            def _flush_manifests() -> None:
                if manifest_batch:
                    batch = list(manifest_batch)
                    manifest_batch.clear()
                    futures.append(
                        pool.submit(_process_manifest_batch, batch, self._cache)
                    )

            # Walk all specified directories to discover files
            for path, kind in walk_specified_dirs(
                scan_dirs + self._extra_dirs
            ):
                if stop_event and stop_event.is_set():
                    logger.info("%s scan aborted by stop event.", label)
                    break

                seen_paths.add(path)

                # In-memory cache check — no SQL query, no file open
                cached = cached_stats.get(path)
                if cached is not None:
                    try:
                        st = os.stat(path)
                        if cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                            continue  # Unchanged — skip parsing entirely
                    except OSError:
                        continue

                # New or modified — queue for parsing
                if kind == EntryKind.MANIFEST:
                    manifest_batch.append(path)
                    if len(manifest_batch) >= _MANIFEST_BATCH_SIZE:
                        _flush_manifests()
                else:
                    binary_batch.append(path)
                    if len(binary_batch) >= _BINARY_BATCH_SIZE:
                        _flush_binaries()

            _flush_binaries()
            _flush_manifests()

            for future in as_completed(futures):
                try:
                    new_items.extend(future.result())
                except Exception as exc:
                    logger.warning("%s worker error: %s", label, exc)

        # ── Deletion detection ─────────────────────────────────────────────
        # Only check paths that are under one of our scan roots so we don't
        # incorrectly report deletions for paths outside the current scan scope.
        norm_roots = [os.path.normcase(d) for d in scan_dirs + self._extra_dirs]
        removed_items: List[SoftwareItem] = []

        for cached_path, _ in cached_stats.items():
            if cached_path in seen_paths:
                continue
            norm_path = os.path.normcase(cached_path)
            if not any(norm_path.startswith(root) for root in norm_roots):
                continue  # Outside the scan scope for this run — don't flag
            # File was present in cache but not found during walk: deleted
            removed_items.extend(self._cache.get_items_for_path(cached_path))
            self._cache.evict(cached_path)

        elapsed = time.perf_counter() - t0
        logger.info(
            "%s scan done: %d paths seen, %d files parsed, %d items found, "
            "%d items removed, %.1f s elapsed",
            label, len(seen_paths), len(binary_batch) + len(manifest_batch),
            len(new_items), len(removed_items), elapsed,
        )
        return new_items, removed_items

    def _emit_fs_delta(
        self,
        new_items: List[SoftwareItem],
        removed_items: List[SoftwareItem],
        on_delta: Optional[Callable[[List[dict], List[dict]], None]],
    ) -> None:
        """
        Merge new/removed filesystem items into the snapshot and call
        on_delta if any changes exist.  Deduplication priority rules apply:
        higher-priority sources (registry) always win over lower ones (PE).
        """
        unique_new = self._deduplicate(new_items)
        added_dicts: List[dict] = []
        removed_dicts: List[dict] = [d.to_api_dict() for d in removed_items]

        with self._snapshot_lock:
            for item in unique_new:
                key = item.dedup_key()
                existing = self._last_snapshot.get(key)
                existing_prio = _SOURCE_PRIORITY.get(
                    existing.source if existing else "", _DEFAULT_PRIORITY
                )
                new_prio = _SOURCE_PRIORITY.get(item.source, _DEFAULT_PRIORITY)
                if existing is None or new_prio < existing_prio:
                    self._last_snapshot[key] = item
                    if existing is None:   # Genuinely new to the snapshot
                        api_d = item.to_api_dict()
                        api_d["change_type"] = "added"
                        added_dicts.append(api_d)

            for item in removed_items:
                key = item.dedup_key()
                # Only remove from snapshot if it was present as a filesystem
                # source — registry items are managed by run_registry_delta()
                existing = self._last_snapshot.get(key)
                if existing and existing.source not in (
                    "registry", "windows_store", "driver", "os"
                ):
                    del self._last_snapshot[key]

        for d in removed_dicts:
            d["change_type"] = "removed"

        if (added_dicts or removed_dicts) and on_delta:
            on_delta(added_dicts, removed_dicts)

    def start_periodic_scans(
        self,
        on_delta: Optional[Callable[[List[dict], List[dict]], None]] = None,
    ) -> None:
        """
        Start the periodic incremental filesystem scan in a daemon thread.

        The thread runs indefinitely until stop_background_scan() is called.
        It performs two kinds of scans on independent schedules:

          Priority scan (every fs_scan_interval_hours, default 4h)
          ─────────────────────────────────────────────────────────
          Traverses well-known software locations (Program Files, AppData,
          Downloads, Desktop, custom drive-root directories).  Covers the
          vast majority of installed software.  The SQLite cache makes
          warm runs fast — only new or modified files are parsed; unchanged
          files are skipped after a single in-memory dict lookup.

          Deep scan (every deep_scan_interval_hours, default 24h)
          ──────────────────────────────────────────────────────────
          Full recursive walk of all local fixed drives.  Catches software
          in non-standard locations (nested developer setups, embedded tools
          in project directories, etc.).  Still uses the same incremental
          cache so only changed files trigger parsing.

        IMPORTANT: Directory traversal STILL happens on every scan to
        discover newly created files.  The cache eliminates file *parsing*
        for unchanged files — it does not skip traversal.

        Parameters
        ──────────
        on_delta
            Called after each scan with (added_dicts, removed_dicts).
            Both lists are API-ready for ZeroWatchClient.sync_delta().
            If None, results are merged into the snapshot silently.
        """
        if self._bg_thread and self._bg_thread.is_alive():
            logger.debug("Periodic scan thread already running; skipping.")
            return

        self._bg_stop.clear()
        is_cold_start = not bool(self._cache.get_meta("last_fs_scan_at"))

        def _periodic_worker() -> None:
            nonlocal is_cold_start

            # On first ever run, do a deep scan immediately to populate the
            # cache.  On warm starts, the priority scan runs first.
            last_priority_scan = 0.0
            last_deep_scan = 0.0

            if is_cold_start:
                logger.info("Cold start detected — running initial deep scan on all drives.")
            else:
                logger.info(
                    "Warm start detected — cache loaded. "
                    "Priority scan will run in %.0f min.",
                    self._fs_scan_interval / 60,
                )

            while not self._bg_stop.is_set():
                now = time.time()

                run_deep     = (
                    is_cold_start
                    or (
                        self._deep_scan_interval > 0
                        and now - last_deep_scan >= self._deep_scan_interval
                    )
                )
                run_priority = (
                    not run_deep
                    and now - last_priority_scan >= self._fs_scan_interval
                )

                if run_deep:
                    try:
                        logger.info("Starting deep scan (all fixed drives).")
                        # Deep scan uses walk_drives() instead of walk_specified_dirs()
                        new_items, removed_items = self._run_full_drive_scan(
                            stop_event=self._bg_stop
                        )
                        self._emit_fs_delta(new_items, removed_items, on_delta)
                        self._cache.set_meta("last_fs_scan_at", self._utc_now_iso())
                        last_deep_scan = time.time()
                        last_priority_scan = last_deep_scan  # Reset priority timer too
                        is_cold_start = False
                    except Exception as exc:
                        logger.error("Deep scan error: %s", exc, exc_info=True)

                elif run_priority:
                    try:
                        logger.info("Starting priority scan (high-value paths).")
                        scan_dirs = get_priority_scan_dirs()
                        new_items, removed_items = self._run_incremental_scan(
                            scan_dirs, stop_event=self._bg_stop, label="priority"
                        )
                        self._emit_fs_delta(new_items, removed_items, on_delta)
                        last_priority_scan = time.time()
                    except Exception as exc:
                        logger.error("Priority scan error: %s", exc, exc_info=True)

                # Sleep in short intervals so stop_event is checked promptly
                self._bg_stop.wait(timeout=60)

        self._bg_thread = threading.Thread(
            target=_periodic_worker,
            name="scanner-periodic",
            daemon=True,
        )
        self._bg_thread.start()
        logger.info(
            "Periodic scan thread started (priority every %.0fh, deep every %.0fh).",
            self._fs_scan_interval / 3600,
            self._deep_scan_interval / 3600,
        )

    def stop_periodic_scans(self, timeout: float = 10.0) -> None:
        """Signal the background scan thread to stop and wait for it to exit."""
        if self._bg_thread and self._bg_thread.is_alive():
            logger.info("Stopping periodic scan thread for re-enrollment reset.")
            self._bg_stop.set()
            self._bg_thread.join(timeout=timeout)
        self._bg_thread = None
        self._bg_stop.clear()

    def reset_for_reenrollment(self) -> None:
        """Clear cached scan timestamps so next start_periodic_scans() does a cold deep scan."""
        try:
            self._cache.delete_meta("last_fs_scan_at")
            logger.info("Scan cache reset for re-enrollment: next scan will be a cold deep scan.")
        except Exception as e:
            logger.warning("Failed to reset scan cache for re-enrollment: %s", e)


    def _run_full_drive_scan(
        self,
        stop_event: Optional[threading.Event] = None,
    ) -> Tuple[List[SoftwareItem], List[SoftwareItem]]:
        """
        Deep scan variant: uses walk_drives() to traverse all fixed drives
        from root (with existing skip rules) instead of a directory list.
        Uses the same incremental cache logic as _run_incremental_scan().
        """
        t0 = time.perf_counter()
        cached_stats: Dict[str, tuple] = self._cache.all_cached_stats()
        seen_paths: Set[str] = set()
        new_items: List[SoftwareItem] = []
        binary_batch:   List[str] = []
        manifest_batch: List[str] = []
        futures = []

        with ThreadPoolExecutor(
            max_workers=self._max_workers, thread_name_prefix="scanner"
        ) as pool:

            def _flush_binaries() -> None:
                if binary_batch:
                    batch = list(binary_batch)
                    binary_batch.clear()
                    futures.append(
                        pool.submit(_process_binary_batch, batch, self._cache, self._binary_inspector)
                    )

            def _flush_manifests() -> None:
                if manifest_batch:
                    batch = list(manifest_batch)
                    manifest_batch.clear()
                    futures.append(
                        pool.submit(_process_manifest_batch, batch, self._cache)
                    )

            for path, kind in self._filesystem_walker.walk_filesystem(extra_dirs=self._extra_dirs):
                if stop_event and stop_event.is_set():
                    break
                seen_paths.add(path)
                cached = cached_stats.get(path)
                if cached is not None:
                    try:
                        st = os.stat(path)
                        if cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                            cached_items = self._cache.get_items_for_path(path)
                            new_items.extend(cached_items)
                            continue
                    except OSError:
                        continue
                if kind == EntryKind.MANIFEST:
                    manifest_batch.append(path)
                    if len(manifest_batch) >= _MANIFEST_BATCH_SIZE:
                        _flush_manifests()
                else:
                    binary_batch.append(path)
                    if len(binary_batch) >= _BINARY_BATCH_SIZE:
                        _flush_binaries()

            _flush_binaries()
            _flush_manifests()
            for future in as_completed(futures):
                try:
                    new_items.extend(future.result())
                except Exception as exc:
                    logger.warning("Deep scan worker error: %s", exc)

        # Deletion detection (all cached paths not seen during walk)
        removed_items: List[SoftwareItem] = []
        for cached_path in cached_stats:
            if cached_path not in seen_paths:
                removed_items.extend(self._cache.get_items_for_path(cached_path))
                self._cache.evict(cached_path)

        elapsed = time.perf_counter() - t0
        logger.info(
            "Deep scan done: %d paths seen, %d new items, %d removed in %.1f s",
            len(seen_paths), len(new_items), len(removed_items), elapsed,
        )
        return new_items, removed_items

    def stop_background_scan(self) -> None:
        """Signal the periodic scan thread to stop gracefully."""
        self._bg_stop.set()

    def load_snapshot_from_cache(self) -> None:
        """
        Load the complete cached inventory into the in-memory snapshot.

        Called once at startup.  After this call the agent has a full
        software inventory without waiting for any filesystem scan to
        complete.  The periodic scan will then emit only deltas (additions
        and removals) as it discovers changes since the last run.
        """
        cached_items = self._cache.all_cached_items()
        if not cached_items:
            logger.info("Scan cache is empty (first run or invalidated).")
            return
        with self._snapshot_lock:
            self._last_snapshot = {
                item.dedup_key(): item for item in cached_items
            }
        logger.info(
            "Warm start: loaded %d items from scan cache.", len(cached_items)
        )

    def close(self) -> None:
        """Clean shutdown: stop the periodic scan thread, close the cache."""
        self.stop_background_scan()
        self._cache.close()


# ── Thread pool worker functions (module-level for picklability) ──────────────

def _process_binary_batch(
    paths: List[str], cache: ScanCache, inspector: Optional[BinaryInspector] = None
) -> List[SoftwareItem]:
    items: List[SoftwareItem] = []
    for path in paths:
        try:
            if inspector is not None:
                items.extend(inspector.inspect_binary(path, cache=cache))
            else:
                from .layer1_paths import inspect_pe_file
                items.extend(inspect_pe_file(path, cache=cache))
        except Exception as exc:
            logger.debug("Binary error %s: %s", path, exc)
    return items


def _process_manifest_batch(
    paths: List[str], cache: ScanCache
) -> List[SoftwareItem]:
    items: List[SoftwareItem] = []
    for path in paths:
        try:
            items.extend(parse_manifest_file(path, cache=cache))
        except Exception as exc:
            logger.debug("Manifest error %s: %s", path, exc)
    return items

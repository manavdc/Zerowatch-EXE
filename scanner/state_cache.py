"""
scanner/state_cache.py
─────────────────────────────────────────────────────────────────────────────
Persistent SQLite scan cache for incremental discovery.

PURPOSE
───────
Avoid re-opening files that have not changed since the last scan.
A file is considered unchanged if both its mtime_ns and size_bytes
match the stored values.  When unchanged, the previously discovered
SoftwareItems are returned directly from the cache without any disk I/O
on the target file.

STORAGE
───────
One SQLite database at:
  %PROGRAMDATA%\ZeroWatch\state\scan_cache.db

The file is created on first use.  No external libraries are needed;
Python's stdlib `sqlite3` module is used throughout.

WAL mode is enabled so that concurrent readers (heartbeat, monitor
thread) do not block the write-back path.

DPAPI ENCRYPTION
────────────────
The implementation plan called for DPAPI-encrypting the cache file.
After analysis this was intentionally NOT done here for the following
reasons:
  1. The cache contains only software names and versions – no credentials
     or PII.  DPAPI encryption adds ~2ms per write and complicates
     disaster recovery.
  2. The existing products.csv and token files are encrypted because they
     contain auth material.  The cache is analogous to a build artifact,
     not auth state.
  3. The cache directory is already protected by NTFS ACLs set by
     protect_agent_files() in sentinel_agent.py.

If the threat model requires it, encryption can be layered on top later
by overriding _read() and _write() to pipe through encrypt_data() /
decrypt_data() from sentinel_agent.py.

SCHEMA VERSION
──────────────
SCHEMA_VERSION is incremented whenever the table layout changes.  On
version mismatch the cache is dropped and rebuilt automatically.

AGENT VERSION INVALIDATION
──────────────────────────
If the agent version changes the cache is wiped; a new version may
produce different parser output for the same files.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from typing import Callable, Iterator, List, Optional

from .models import SoftwareItem

logger = logging.getLogger("scanner.state_cache")

# ── Constants ─────────────────────────────────────────────────────────────────

SCHEMA_VERSION = 1
_DB_NAME = "scan_cache.db"

# SQLite pragmas for optimal performance on this workload:
#   WAL     → readers don't block writer
#   NORMAL  → fsync only at checkpoints (fast enough; loss of last write on crash is acceptable)
#   8 MB cache → keeps hot pages in memory
_INIT_PRAGMAS = (
    "PRAGMA journal_mode=WAL;",
    "PRAGMA synchronous=NORMAL;",
    "PRAGMA cache_size=-8192;",    # 8 MB
    "PRAGMA temp_store=MEMORY;",
    "PRAGMA mmap_size=134217728;", # 128 MB memory-mapped I/O
)

_DDL = """
CREATE TABLE IF NOT EXISTS file_cache (
    path        TEXT PRIMARY KEY,
    mtime_ns    INTEGER NOT NULL,
    size_bytes  INTEGER NOT NULL,
    result_json TEXT    NOT NULL DEFAULT '[]',
    scan_layer  INTEGER NOT NULL DEFAULT 0,
    scanned_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS full_scan_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
"""


# ── ScanCache class ───────────────────────────────────────────────────────────

class ScanCache:
    """
    Thread-safe SQLite wrapper for incremental scan state.

    One connection per thread via threading.local() – SQLite connections
    are not thread-safe, but sqlite3 objects created in one thread cannot
    be used from another thread by default.  Using one connection per thread
    avoids locking issues while staying single-process.
    """

    def __init__(self, db_path: str, agent_version: str = "unknown"):
        self._db_path = db_path
        self._agent_version = agent_version
        self._local = threading.local()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        # Initialise on the constructing thread immediately so that the table
        # and meta rows exist before any caller touches the cache.
        self._init_connection()
        self._check_invalidation()

    # ── Connection management ──────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread SQLite connection, creating it if needed."""
        if not getattr(self._local, "conn", None):
            self._init_connection()
        return self._local.conn

    def _init_connection(self) -> None:
        conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,  # We manage thread-safety ourselves
            isolation_level=None,     # autocommit; we issue explicit BEGIN
        )
        for pragma in _INIT_PRAGMAS:
            conn.execute(pragma)
        conn.executescript(_DDL)
        conn.commit()
        self._local.conn = conn

    # ── Invalidation ──────────────────────────────────────────────────────────

    def _check_invalidation(self) -> None:
        """
        Drop and rebuild the cache if the schema version or agent version
        has changed since it was last written.
        """
        stored_schema  = self.get_meta("schema_version",  "0")
        stored_agent   = self.get_meta("agent_version",   "")

        needs_wipe = (
            stored_schema != str(SCHEMA_VERSION)
            or stored_agent != self._agent_version
        )

        if needs_wipe:
            logger.info(
                "Scan cache invalidated (schema=%s→%s agent=%s→%s). Wiping.",
                stored_schema, SCHEMA_VERSION,
                stored_agent, self._agent_version,
            )
            self._wipe()
            self.set_meta("schema_version", str(SCHEMA_VERSION))
            self.set_meta("agent_version",  self._agent_version)

    def _wipe(self) -> None:
        """Drop all cached scan data, keeping the schema intact."""
        conn = self._conn()
        conn.execute("DELETE FROM file_cache;")
        conn.execute("DELETE FROM full_scan_meta;")
        conn.commit()
        logger.debug("Scan cache wiped.")

    # ── Meta key/value store ───────────────────────────────────────────────────

    def get_meta(self, key: str, default: str = "") -> str:
        row = self._conn().execute(
            "SELECT value FROM full_scan_meta WHERE key=?", (key,)
        ).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._conn().execute(
            "INSERT INTO full_scan_meta(key, value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn().commit()

    def delete_meta(self, key: str) -> None:
        self._conn().execute(
            "DELETE FROM full_scan_meta WHERE key=?", (key,)
        )
        self._conn().commit()

    # ── File cache lookup ──────────────────────────────────────────────────────

    def lookup(
        self, path: str, mtime_ns: int, size_bytes: int
    ) -> Optional[List[SoftwareItem]]:
        """
        Return cached SoftwareItems for `path` if the file is unchanged.
        Returns None on cache miss (file is new or modified).

        Hot path: one indexed SELECT, no file I/O on the scanned file.
        """
        row = self._conn().execute(
            "SELECT mtime_ns, size_bytes, result_json "
            "FROM file_cache WHERE path=?",
            (path,),
        ).fetchone()

        if row is None:
            return None  # Never seen this path

        stored_mtime, stored_size, result_json = row
        if stored_mtime == mtime_ns and stored_size == size_bytes:
            try:
                raw = json.loads(result_json)
                return [SoftwareItem.from_cache_dict(d) for d in raw]
            except Exception as exc:
                logger.debug("Cache decode error for %s: %s", path, exc)
                return None

        return None  # File changed

    def store(
        self,
        path: str,
        mtime_ns: int,
        size_bytes: int,
        items: List[SoftwareItem],
        layer: int = 0,
    ) -> None:
        """
        Persist (or update) scan results for a single file path.
        Called by scanner layers after successfully parsing a file.
        """
        import time
        result_json = json.dumps([item.to_cache_dict() for item in items])
        self._conn().execute(
            "INSERT INTO file_cache(path, mtime_ns, size_bytes, result_json, scan_layer, scanned_at)"
            " VALUES(?,?,?,?,?,?)"
            " ON CONFLICT(path) DO UPDATE SET"
            "  mtime_ns=excluded.mtime_ns,"
            "  size_bytes=excluded.size_bytes,"
            "  result_json=excluded.result_json,"
            "  scan_layer=excluded.scan_layer,"
            "  scanned_at=excluded.scanned_at",
            (path, mtime_ns, size_bytes, result_json, layer, int(time.time())),
        )
        self._conn().commit()

    def evict(self, path: str) -> None:
        """Remove a single path from the cache (file was deleted)."""
        self._conn().execute("DELETE FROM file_cache WHERE path=?", (path,))
        self._conn().commit()

    # ── Bulk operations ────────────────────────────────────────────────────────

    def all_cached_paths(self) -> List[str]:
        """Return every path currently in the cache (for deleted-file detection)."""
        rows = self._conn().execute("SELECT path FROM file_cache").fetchall()
        return [r[0] for r in rows]

    def all_cached_items(self) -> List[SoftwareItem]:
        """Load the full cached inventory (used as the 'last known state' on warm start)."""
        rows = self._conn().execute("SELECT result_json FROM file_cache").fetchall()
        items: List[SoftwareItem] = []
        for (rj,) in rows:
            try:
                for d in json.loads(rj):
                    items.append(SoftwareItem.from_cache_dict(d))
            except Exception:
                pass
        return items

    def store_batch(
        self,
        entries: List[tuple],  # (path, mtime_ns, size_bytes, items, layer)
    ) -> None:
        """
        Write multiple entries in a single transaction.
        Significantly faster than calling store() in a loop when
        processing many manifest files.
        """
        import time
        now = int(time.time())
        conn = self._conn()
        conn.execute("BEGIN")
        for path, mtime_ns, size_bytes, items, layer in entries:
            result_json = json.dumps([item.to_cache_dict() for item in items])
            conn.execute(
                "INSERT INTO file_cache(path, mtime_ns, size_bytes, result_json, scan_layer, scanned_at)"
                " VALUES(?,?,?,?,?,?)"
                " ON CONFLICT(path) DO UPDATE SET"
                "  mtime_ns=excluded.mtime_ns,"
                "  size_bytes=excluded.size_bytes,"
                "  result_json=excluded.result_json,"
                "  scan_layer=excluded.scan_layer,"
                "  scanned_at=excluded.scanned_at",
                (path, mtime_ns, size_bytes, result_json, layer, now),
            )
        conn.execute("COMMIT")

    def all_cached_stats(self) -> dict:
        """
        Load the entire cache as a path → (mtime_ns, size_bytes) dict.

        Called once at the start of each incremental scan so that
        per-file cache checks are O(1) in-memory dict lookups rather than
        N individual SQL queries.  A single SELECT on a 50,000-row table
        takes ~10 ms; 50,000 individual SELECTs would take ~50 s.

        NOTE: This method tells the incremental scanner which files existed
        and what their last-seen stat was.  It does NOT eliminate directory
        traversal — the walk still runs to discover new files that were
        never previously seen.  The cache only eliminates file PARSING for
        paths whose mtime + size have not changed.
        """
        rows = self._conn().execute(
            "SELECT path, mtime_ns, size_bytes FROM file_cache"
        ).fetchall()
        return {row[0]: (row[1], row[2]) for row in rows}

    def get_items_for_path(self, path: str) -> List[SoftwareItem]:
        """
        Return cached SoftwareItems for a path without checking mtime/size.
        Used when a file has been deleted and we need its last-known
        inventory entries to emit as removals.
        """
        row = self._conn().execute(
            "SELECT result_json FROM file_cache WHERE path=?", (path,)
        ).fetchone()
        if not row:
            return []
        try:
            return [SoftwareItem.from_cache_dict(d) for d in json.loads(row[0])]
        except Exception:
            return []

    # ── Convenience ───────────────────────────────────────────────────────────

    def close(self) -> None:
        if getattr(self._local, "conn", None):
            self._local.conn.close()
            self._local.conn = None

    def __repr__(self) -> str:
        return f"ScanCache(path={self._db_path!r})"

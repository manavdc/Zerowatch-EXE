"""
common/scanner/state_cache.py
─────────────────────────────────────────────────────────────────────────────
Persistent SQLite scan cache for incremental discovery.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from typing import Callable, Iterator, List, Optional

from common.scanner.models import SoftwareItem

logger = logging.getLogger("scanner.state_cache")

# ── Constants ─────────────────────────────────────────────────────────────────

SCHEMA_VERSION = 1
_DB_NAME = "scan_cache.db"

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
    """

    def __init__(self, db_path: str, agent_version: str = "unknown"):
        self._db_path = db_path
        self._agent_version = agent_version
        self._local = threading.local()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_connection()
        self._check_invalidation()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._init_connection()
        return self._local.conn

    def _init_connection(self) -> None:
        conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            isolation_level=None,
        )
        for pragma in _INIT_PRAGMAS:
            conn.execute(pragma)
        conn.executescript(_DDL)
        conn.commit()
        self._local.conn = conn

    def _check_invalidation(self) -> None:
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
        conn = self._conn()
        conn.execute("DELETE FROM file_cache;")
        conn.execute("DELETE FROM full_scan_meta;")
        conn.commit()
        logger.debug("Scan cache wiped.")

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

    def lookup(
        self, path: str, mtime_ns: int, size_bytes: int
    ) -> Optional[List[SoftwareItem]]:
        row = self._conn().execute(
            "SELECT mtime_ns, size_bytes, result_json "
            "FROM file_cache WHERE path=?",
            (path,),
        ).fetchone()

        if row is None:
            return None

        stored_mtime, stored_size, result_json = row
        if stored_mtime == mtime_ns and stored_size == size_bytes:
            try:
                raw = json.loads(result_json)
                return [SoftwareItem.from_cache_dict(d) for d in raw]
            except Exception as exc:
                logger.debug("Cache decode error for %s: %s", path, exc)
                return None

        return None

    def store(
        self,
        path: str,
        mtime_ns: int,
        size_bytes: int,
        items: List[SoftwareItem],
        layer: int = 0,
    ) -> None:
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
        self._conn().execute("DELETE FROM file_cache WHERE path=?", (path,))
        self._conn().commit()

    def all_cached_paths(self) -> List[str]:
        rows = self._conn().execute("SELECT path FROM file_cache").fetchall()
        return [r[0] for r in rows]

    def all_cached_items(self) -> List[SoftwareItem]:
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
        entries: List[tuple],
    ) -> None:
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
        rows = self._conn().execute(
            "SELECT path, mtime_ns, size_bytes FROM file_cache"
        ).fetchall()
        return {row[0]: (row[1], row[2]) for row in rows}

    def get_items_for_path(self, path: str) -> List[SoftwareItem]:
        row = self._conn().execute(
            "SELECT result_json FROM file_cache WHERE path=?", (path,)
        ).fetchone()
        if not row:
            return []
        try:
            return [SoftwareItem.from_cache_dict(d) for d in json.loads(row[0])]
        except Exception:
            return []

    def close(self) -> None:
        if getattr(self._local, "conn", None):
            self._local.conn.close()
            self._local.conn = None

    def __repr__(self) -> str:
        return f"ScanCache(path={self._db_path!r})"

"""
macos/persistence/startup_manager.py
─────────────────────────────────────────────────────────────────────────────
macOS implementation stub of PersistenceManager interface.
Pending Phase 6B implementation.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from common.persistence.interfaces import PersistenceManager

logger = logging.getLogger("macos.persistence.startup")


class MacOSPersistenceManager(PersistenceManager):
    """
    macOS implementation stub of PersistenceManager using launchd.

    Planned Phase 6B Strategy:
      - System Daemon (root): /Library/LaunchDaemons/io.deepcytes.zerowatch-agent.plist
      - User Agent (logon):   ~/Library/LaunchAgents/io.deepcytes.zerowatch-agent.plist
    """

    def register_startup(
        self,
        exe_path: str,
        daemon_args: Optional[List[str]] = None,
    ) -> bool:
        raise NotImplementedError("MacOSPersistenceManager is scheduled for Phase 6B.")

    def unregister_startup(self) -> bool:
        raise NotImplementedError("MacOSPersistenceManager is scheduled for Phase 6B.")

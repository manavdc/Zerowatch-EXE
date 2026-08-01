"""
windows/persistence package
Windows PersistenceManager implementations.
"""

from .startup_manager import (
    WindowsPersistenceManager,
    register_startup_registry,
    unregister_startup_registry,
)

__all__ = [
    "WindowsPersistenceManager",
    "register_startup_registry",
    "unregister_startup_registry",
]

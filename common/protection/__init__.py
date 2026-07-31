"""
common/protection package
Agent process self-defense and audit event logging interfaces.
"""

from .interfaces import ProcessGuard, EventLogger

__all__ = ["ProcessGuard", "EventLogger"]

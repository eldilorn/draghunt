"""SIEM adapter seam.

Draghunt is SIEM-agnostic everywhere except one place: pulling the alerts for
an investigation window. That single operation lives behind this interface, so
Wazuh is just the first adapter and any other SIEM (Splunk, Elastic, ...) is a
new class, not a fork of the app.

To add a SIEM: subclass SiemAdapter, implement `query_alerts`, and register it
with @register("name"). Users select it with `siem.adapter = "name"` in
range.toml.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable


@dataclass
class Alert:
    """A normalized alert, so the UI renders the same shape for every SIEM."""

    timestamp: str
    rule: str
    level: int | str
    source: str          # agent / host the alert came from
    description: str
    raw: dict[str, Any]
    event_id: str = ""


@dataclass
class AlertBatch:
    alerts: list[Alert]
    total: int
    complete: bool
    detail: str = ""


class SiemAdapter(ABC):
    name: str = "base"

    def __init__(self, options: dict[str, Any]):
        self.options = options

    @abstractmethod
    def query_alerts(self, start: datetime, end: datetime, limit: int = 200) -> list[Alert]:
        """Return alerts between start and end (UTC). Implemented per SIEM."""

    def collect(self, start: datetime, end: datetime, agent_id: str, limit: int = 2000,
                kind: str = "alerts") -> AlertBatch:
        raise NotImplementedError("this adapter does not support scoped evidence collection")

    def health(self) -> tuple[bool, str]:
        """Cheap reachability check. Override; default says 'unknown'."""
        return (False, "health check not implemented for this adapter")


_REGISTRY: dict[str, type[SiemAdapter]] = {}


def register(name: str) -> Callable[[type[SiemAdapter]], type[SiemAdapter]]:
    def deco(cls: type[SiemAdapter]) -> type[SiemAdapter]:
        cls.name = name
        _REGISTRY[name] = cls
        return cls
    return deco


def get_adapter(name: str, options: dict[str, Any]) -> SiemAdapter:
    # import built-ins so their @register runs
    from . import wazuh  # noqa: F401

    if name not in _REGISTRY:
        raise KeyError(f"no SIEM adapter '{name}'; have {sorted(_REGISTRY)}")
    return _REGISTRY[name](options)


def available() -> list[str]:
    from . import wazuh  # noqa: F401
    return sorted(_REGISTRY)

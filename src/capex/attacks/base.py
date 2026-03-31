from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from capex.models import AttackConfig, DeviceConfig


class AttackRenderer(Protocol):
    def render(self, attack: AttackConfig, device: DeviceConfig) -> list[str]: ...

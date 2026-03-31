from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capex.models import AttackConfig, DeviceConfig


class TemplateAttackRenderer:
    def render(self, attack: AttackConfig, device: DeviceConfig) -> list[str]:
        return [part.format(target_ip=str(device.ip), device_name=device.name) for part in attack.command]

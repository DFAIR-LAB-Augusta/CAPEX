from __future__ import annotations

from typing import TYPE_CHECKING

from capex.exceptions import AttackExecutionError

if TYPE_CHECKING:
    from capex.models import CommandAttackConfig, DeviceConfig, PlaceholderAttackConfig
    from capex.runner import CommandRunner


class CommandAttackExecutor:
    def __init__(
        self,
        *,
        runner: CommandRunner,
        attack: CommandAttackConfig,
    ) -> None:
        self._runner = runner
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        rendered = [
            token.format(
                target_ip=str(device.ip),
                device_name=device.name,
            )
            for token in self._attack.command
        ]
        self._runner.run(rendered)
        return None


class PlaceholderAttackExecutor:
    def __init__(self, *, attack: PlaceholderAttackConfig) -> None:
        self._attack = attack

    def execute(self, *, device: DeviceConfig) -> str | None:
        raise AttackExecutionError(f'Attack "{self._attack.name}" is disabled: {self._attack.reason}')

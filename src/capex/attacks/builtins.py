from __future__ import annotations

import time

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

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

    def execute(
        self,
        *,
        device: DeviceConfig,
        log_path: Path,
    ) -> None:
        rendered = [
            token.format(
                target_ip=str(device.ip),
                device_name=device.name,
            )
            for token in self._attack.command
        ]
        self._runner.run(rendered)
        with log_path.open('a', encoding='utf-8') as handle:
            handle.write(f'attack={self._attack.label} device={device.name} timestamp={time.time()}\n')


class PlaceholderAttackExecutor:
    def __init__(self, *, attack: PlaceholderAttackConfig) -> None:
        self._attack = attack

    def execute(
        self,
        *,
        device: DeviceConfig,
        log_path: Path,
    ) -> None:
        raise RuntimeError(f'Attack "{self._attack.name}" is disabled: {self._attack.reason}')

from __future__ import annotations

from typing import TYPE_CHECKING

from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.hulk import HulkAttackExecutor

if TYPE_CHECKING:
    from capex.attacks.base import BoundAttackExecutor
    from capex.models import AttackConfig
    from capex.runner import CommandRunner


class AttackRegistry:
    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def resolve(self, attack: AttackConfig) -> BoundAttackExecutor:
        match attack.kind:
            case 'command':
                return CommandAttackExecutor(
                    runner=self._runner,
                    attack=attack,
                )
            case 'placeholder':
                return PlaceholderAttackExecutor(
                    attack=attack,
                )
            case 'hulk':
                return HulkAttackExecutor(
                    runner=self._runner,
                    attack=attack,
                )
            case _:
                msg = f'Unsupported attack kind: {attack.kind}'
                raise ValueError(msg)

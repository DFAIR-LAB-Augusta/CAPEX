from __future__ import annotations

from typing import TYPE_CHECKING

from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.c2 import C2BeaconExecutor
from capex.attacks.hulk import HulkAttackExecutor
from capex.exceptions import RegistryError

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
                    attack=attack,
                )
            case 'c2_beacon':
                return C2BeaconExecutor(
                    attack=attack,
                )
            case _:
                msg = f'Unsupported attack kind: {attack.kind}'
                raise RegistryError(msg)

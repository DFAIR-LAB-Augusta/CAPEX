from __future__ import annotations

import pytest

from capex.attacks.builtins import PlaceholderAttackExecutor
from capex.exceptions import AttackExecutionError
from capex.models import DeviceConfig, PlaceholderAttackConfig


def test_placeholder_executor_raises_attack_execution_error() -> None:
    attack = PlaceholderAttackConfig(name='legacy', label='legacy', reason='not implemented yet')
    executor = PlaceholderAttackExecutor(attack=attack)
    device = DeviceConfig(name='dev1', ip='192.168.1.1')

    with pytest.raises(AttackExecutionError, match='not implemented yet'):
        executor.execute(device=device)

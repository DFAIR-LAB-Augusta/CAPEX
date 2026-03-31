from __future__ import annotations

from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.registry import AttackRegistry
from capex.models import CommandAttackConfig, PlaceholderAttackConfig
from capex.runner import CommandRunner


def test_registry_resolves_command_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = CommandAttackConfig(
        name='udp_flood',
        label='UDP_Flood',
        kind='command',
        command=['echo', '{target_ip}'],
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, CommandAttackExecutor)


def test_registry_resolves_placeholder_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = PlaceholderAttackConfig(
        name='legacy_hulk',
        label='HULK_HTTP_Flood',
        kind='placeholder',
        reason='disabled',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, PlaceholderAttackExecutor)

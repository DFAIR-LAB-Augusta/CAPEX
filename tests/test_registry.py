from __future__ import annotations

import types

import pytest

from capex.attacks.arp import ArpSpoofExecutor
from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.hulk import HulkAttackExecutor
from capex.attacks.registry import AttackRegistry
from capex.exceptions import RegistryError
from capex.models import ArpSpoofAttackConfig, CommandAttackConfig, HulkAttackConfig, PlaceholderAttackConfig
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
        name='legacy_placeholder',
        label='Legacy_Placeholder',
        kind='placeholder',
        reason='disabled',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, PlaceholderAttackExecutor)


def test_registry_resolves_hulk_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = HulkAttackConfig(
        name='hulk_http_flood',
        label='HULK_HTTP_Flood',
        kind='hulk',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, HulkAttackExecutor)


def test_registry_resolves_arp_spoof_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = ArpSpoofAttackConfig(
        name='arp_spoof',
        label='ARP_Spoof',
        interface='eth0',
        gateway_ip='192.168.1.1',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, ArpSpoofExecutor)


def test_registry_raises_registry_error_for_unsupported_kind() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = types.SimpleNamespace(kind='unsupported')

    with pytest.raises(RegistryError, match='Unsupported attack kind'):
        registry.resolve(attack)

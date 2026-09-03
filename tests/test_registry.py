from __future__ import annotations

import types

import pytest

from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.c2 import C2BeaconExecutor
from capex.attacks.c2_dns import DnsC2BeaconExecutor
from capex.attacks.hulk import HulkAttackExecutor
from capex.attacks.registry import AttackRegistry
from capex.exceptions import RegistryError
from capex.models import (
    C2BeaconAttackConfig,
    C2DnsBeaconAttackConfig,
    CommandAttackConfig,
    HulkAttackConfig,
    PlaceholderAttackConfig,
)
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


def test_registry_resolves_c2_beacon_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = C2BeaconAttackConfig(name='c2_beacon', label='C2_Beacon')
    resolved = registry.resolve(attack)
    assert isinstance(resolved, C2BeaconExecutor)


def test_registry_resolves_c2_dns_beacon_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = C2DnsBeaconAttackConfig(name='c2_dns_beacon', label='C2_DNS_Beacon')
    resolved = registry.resolve(attack)
    assert isinstance(resolved, DnsC2BeaconExecutor)


def test_registry_raises_registry_error_for_unsupported_kind() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = types.SimpleNamespace(kind='unsupported')

    with pytest.raises(RegistryError, match='Unsupported attack kind'):
        registry.resolve(attack)

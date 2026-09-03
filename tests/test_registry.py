from __future__ import annotations

import types

import pytest

from capex.attacks.application_layer import HttpFuzzExecutor
from capex.attacks.builtins import CommandAttackExecutor, PlaceholderAttackExecutor
from capex.attacks.credential_access import HydraBruteForceExecutor
from capex.attacks.discovery import BannerGrabExecutor, SsdpDiscoveryExecutor
from capex.attacks.hulk import HulkAttackExecutor
from capex.attacks.registry import AttackRegistry
from capex.exceptions import RegistryError
from capex.models import (
    BannerGrabAttackConfig,
    CommandAttackConfig,
    HttpFuzzAttackConfig,
    HulkAttackConfig,
    HydraBruteForceAttackConfig,
    PlaceholderAttackConfig,
    SsdpDiscoveryAttackConfig,
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


def test_registry_resolves_ssdp_discovery_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = SsdpDiscoveryAttackConfig(
        name='ssdp_discovery',
        label='SSDP_Discovery',
        kind='ssdp_discovery',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, SsdpDiscoveryExecutor)


def test_registry_resolves_banner_grab_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = BannerGrabAttackConfig(
        name='banner_grab',
        label='Banner_Grab',
        kind='banner_grab',
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, BannerGrabExecutor)


def test_registry_resolves_hydra_brute_force_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = HydraBruteForceAttackConfig(
        name='hydra_http_default_creds',
        label='Hydra_HTTP_Default_Creds',
        service='http-get',
        port=80,
        username_list=['admin'],
        password_list=['admin'],
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, HydraBruteForceExecutor)


def test_registry_resolves_http_fuzz_attack() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = HttpFuzzAttackConfig(
        name='http_fuzz',
        label='HTTP_Fuzz',
        paths=['/../../../../etc/passwd'],
    )
    resolved = registry.resolve(attack)
    assert isinstance(resolved, HttpFuzzExecutor)


def test_registry_raises_registry_error_for_unsupported_kind() -> None:
    registry = AttackRegistry(CommandRunner())
    attack = types.SimpleNamespace(kind='unsupported')

    with pytest.raises(RegistryError, match='Unsupported attack kind'):
        registry.resolve(attack)

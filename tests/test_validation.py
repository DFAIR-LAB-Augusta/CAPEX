from __future__ import annotations

import pytest

from capex.exceptions import ConfigError, PathError, ValidationError
from capex.models import CaptureConfig, CommandAttackConfig, DeviceConfig, PlaceholderAttackConfig
from capex.validation import (
    validate_attacks,
    validate_capture_config,
    validate_config_paths,
    validate_devices,
)


def test_validate_capture_config_rejects_large_safe_period() -> None:
    config = CaptureConfig(
        duration_seconds=100,
        safe_period_seconds=100,
    )

    with pytest.raises(ValidationError):
        validate_capture_config(config)


def _command_attack(name: str = 'attack', *, enabled: bool = True) -> CommandAttackConfig:
    return CommandAttackConfig(
        name=name,
        label=name,
        enabled=enabled,
        command=['echo', 'hi'],
    )


def test_validate_attacks_rejects_empty_list() -> None:
    with pytest.raises(ConfigError, match='No attacks were configured'):
        validate_attacks([])


def test_validate_attacks_rejects_duplicate_names() -> None:
    attacks = [_command_attack('dup'), _command_attack('dup')]

    with pytest.raises(ConfigError, match='Duplicate attack names'):
        validate_attacks(attacks)


def test_validate_attacks_rejects_no_enabled_attacks() -> None:
    attacks = [_command_attack('a', enabled=False)]

    with pytest.raises(ConfigError, match='No attacks are enabled'):
        validate_attacks(attacks)


def test_validate_attacks_accepts_disabled_placeholder() -> None:
    attacks = [
        _command_attack('a'),
        PlaceholderAttackConfig(name='legacy', label='legacy', reason='not implemented'),
    ]

    validate_attacks(attacks)


def test_validate_attacks_rejects_enabled_placeholder() -> None:
    attacks = [
        _command_attack('a'),
        PlaceholderAttackConfig(
            name='legacy',
            label='legacy',
            enabled=True,
            reason='not implemented',
        ),
    ]

    with pytest.raises(ConfigError, match='cannot be enabled'):
        validate_attacks(attacks)


def test_validate_devices_rejects_empty_list() -> None:
    with pytest.raises(ConfigError, match='No devices were configured'):
        validate_devices([])


def test_validate_devices_rejects_duplicate_names() -> None:
    devices = [
        DeviceConfig(name='dup', ip='192.168.1.1'),
        DeviceConfig(name='dup', ip='192.168.1.2'),
    ]

    with pytest.raises(ConfigError, match='Duplicate device names'):
        validate_devices(devices)


def test_validate_devices_rejects_duplicate_ips() -> None:
    devices = [
        DeviceConfig(name='a', ip='192.168.1.1'),
        DeviceConfig(name='b', ip='192.168.1.1'),
    ]

    with pytest.raises(ConfigError, match='Duplicate device IPs'):
        validate_devices(devices)


def test_validate_devices_accepts_valid_list() -> None:
    devices = [DeviceConfig(name='a', ip='192.168.1.1')]

    validate_devices(devices)


def test_validate_config_paths_rejects_missing_devices_file(tmp_path) -> None:
    attacks_path = tmp_path / 'attacks.yaml'
    attacks_path.write_text('attacks: []\n', encoding='utf-8')

    with pytest.raises(PathError, match='Devices config not found'):
        validate_config_paths(devices_path=tmp_path / 'missing.yaml', attacks_path=attacks_path)


def test_validate_config_paths_rejects_devices_path_that_is_a_directory(tmp_path) -> None:
    devices_dir = tmp_path / 'devices.yaml'
    devices_dir.mkdir()
    attacks_path = tmp_path / 'attacks.yaml'
    attacks_path.write_text('attacks: []\n', encoding='utf-8')

    with pytest.raises(PathError, match='Devices config is not a file'):
        validate_config_paths(devices_path=devices_dir, attacks_path=attacks_path)


def test_validate_config_paths_rejects_missing_attacks_file(tmp_path) -> None:
    devices_path = tmp_path / 'devices.yaml'
    devices_path.write_text('devices: []\n', encoding='utf-8')

    with pytest.raises(PathError, match='Attacks config not found'):
        validate_config_paths(devices_path=devices_path, attacks_path=tmp_path / 'missing.yaml')


def test_validate_config_paths_rejects_attacks_path_that_is_a_directory(tmp_path) -> None:
    devices_path = tmp_path / 'devices.yaml'
    devices_path.write_text('devices: []\n', encoding='utf-8')
    attacks_dir = tmp_path / 'attacks.yaml'
    attacks_dir.mkdir()

    with pytest.raises(PathError, match='Attacks config is not a file'):
        validate_config_paths(devices_path=devices_path, attacks_path=attacks_dir)


def test_validate_config_paths_accepts_existing_files(tmp_path) -> None:
    devices_path = tmp_path / 'devices.yaml'
    devices_path.write_text('devices: []\n', encoding='utf-8')
    attacks_path = tmp_path / 'attacks.yaml'
    attacks_path.write_text('attacks: []\n', encoding='utf-8')

    validate_config_paths(devices_path=devices_path, attacks_path=attacks_path)

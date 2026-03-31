from __future__ import annotations

from typing import TYPE_CHECKING

from capex.exceptions import ConfigError, PathError, ValidationError

if TYPE_CHECKING:
    from pathlib import Path

    from capex.models import AttackConfig, CaptureConfig, DeviceConfig


def validate_capture_config(config: CaptureConfig) -> None:
    """Validate cross-field capture configuration constraints."""
    if config.safe_period_seconds >= config.duration_seconds:
        msg = (
            'safe_period_seconds must be less than duration_seconds. '
            f'Got safe_period_seconds={config.safe_period_seconds} and '
            f'duration_seconds={config.duration_seconds}.'
        )
        raise ValidationError(msg)


def validate_devices(devices: list[DeviceConfig]) -> None:
    """Validate device collection constraints."""
    if not devices:
        raise ConfigError('No devices were configured.')

    names = [device.name for device in devices]
    duplicate_names = _find_duplicates(names)
    if duplicate_names:
        msg = f'Duplicate device names found: {", ".join(sorted(duplicate_names))}'
        raise ConfigError(msg)

    ips = [str(device.ip) for device in devices]
    duplicate_ips = _find_duplicates(ips)
    if duplicate_ips:
        msg = f'Duplicate device IPs found: {", ".join(sorted(duplicate_ips))}'
        raise ConfigError(msg)


def validate_attacks(attacks: list[AttackConfig]) -> None:
    """Validate attack collection constraints."""
    if not attacks:
        raise ConfigError('No attacks were configured.')

    names = [attack.name for attack in attacks]
    duplicate_names = _find_duplicates(names)
    if duplicate_names:
        msg = f'Duplicate attack names found: {", ".join(sorted(duplicate_names))}'
        raise ConfigError(msg)

    enabled_attacks = [attack for attack in attacks if attack.enabled]
    if not enabled_attacks:
        raise ConfigError('No attacks are enabled.')

    for attack in enabled_attacks:
        if attack.repeats < 1:
            msg = f'Attack {attack.name} must have repeats >= 1.'
            raise ValidationError(msg)


def validate_config_paths(*, devices_path: Path, attacks_path: Path) -> None:
    """Validate that required configuration files exist."""
    if not devices_path.exists():
        raise PathError(f'Devices config not found: {devices_path}')

    if not devices_path.is_file():
        raise PathError(f'Devices config is not a file: {devices_path}')

    if not attacks_path.exists():
        raise PathError(f'Attacks config not found: {attacks_path}')

    if not attacks_path.is_file():
        raise PathError(f'Attacks config is not a file: {attacks_path}')


def _find_duplicates(values: list[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        else:
            seen.add(value)

    return duplicates

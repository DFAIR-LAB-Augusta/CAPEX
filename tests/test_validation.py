from __future__ import annotations

import pytest

from capex.exceptions import ConfigError, ValidationError
from capex.models import CaptureConfig, CommandAttackConfig, PlaceholderAttackConfig
from capex.validation import validate_attacks, validate_capture_config


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

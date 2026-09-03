from __future__ import annotations

import pytest

from capex.config import load_attacks, load_devices
from capex.exceptions import ConfigError


def test_load_devices_raises_config_error_when_top_level_is_not_a_mapping(tmp_path) -> None:
    path = tmp_path / 'devices.yaml'
    path.write_text('- a\n- b\n', encoding='utf-8')

    with pytest.raises(ConfigError, match='Expected mapping'):
        load_devices(path)


def test_load_attacks_raises_config_error_when_top_level_is_not_a_mapping(tmp_path) -> None:
    path = tmp_path / 'attacks.yaml'
    path.write_text('- a\n- b\n', encoding='utf-8')

    with pytest.raises(ConfigError, match='Expected mapping'):
        load_attacks(path)


def test_load_devices_parses_valid_file(tmp_path) -> None:
    path = tmp_path / 'devices.yaml'
    path.write_text(
        'devices:\n  - name: dev1\n    ip: 192.168.1.1\n',
        encoding='utf-8',
    )

    result = load_devices(path)

    assert result.devices[0].name == 'dev1'

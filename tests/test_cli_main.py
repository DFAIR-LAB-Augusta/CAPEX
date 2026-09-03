from __future__ import annotations

import pytest

from capex import cli
from capex.exceptions import PathError

_DEVICES_YAML = """\
devices:
  - name: dev1
    ip: 192.168.1.1
    enabled: true
  - name: dev2
    ip: 192.168.1.2
    enabled: false
"""

_ATTACKS_YAML = """\
attacks:
  - name: a1
    label: A1
    enabled: true
    repeats: 1
    command:
      - echo
      - hi
"""


def _write_configs(tmp_path):
    devices_path = tmp_path / 'devices.yaml'
    attacks_path = tmp_path / 'attacks.yaml'
    devices_path.write_text(_DEVICES_YAML, encoding='utf-8')
    attacks_path.write_text(_ATTACKS_YAML, encoding='utf-8')
    return devices_path, attacks_path


def test_main_dry_run_prints_plan_and_creates_directories(tmp_path, monkeypatch, capsys) -> None:
    devices_path, attacks_path = _write_configs(tmp_path)
    output_dir = tmp_path / 'raw'
    log_dir = tmp_path / 'logs'

    monkeypatch.setattr(
        'sys.argv',
        [
            'capex',
            '--devices',
            str(devices_path),
            '--attacks',
            str(attacks_path),
            '--output-dir',
            str(output_dir),
            '--log-dir',
            str(log_dir),
            '--dry-run',
        ],
    )

    exit_code = cli.main()

    assert exit_code == 0
    assert output_dir.is_dir()
    assert log_dir.is_dir()

    out = capsys.readouterr().out
    assert 'device=dev1 ip=192.168.1.1' in out
    assert 'device=dev2 ip=192.168.1.2' in out
    assert 'attack=a1 repeats=1' in out


def test_main_filters_by_device(tmp_path, monkeypatch, capsys) -> None:
    devices_path, attacks_path = _write_configs(tmp_path)

    monkeypatch.setattr(
        'sys.argv',
        [
            'capex',
            '--devices',
            str(devices_path),
            '--attacks',
            str(attacks_path),
            '--output-dir',
            str(tmp_path / 'raw'),
            '--log-dir',
            str(tmp_path / 'logs'),
            '--device',
            'dev1',
            '--dry-run',
        ],
    )

    cli.main()

    out = capsys.readouterr().out
    assert 'device=dev1' in out
    assert 'device=dev2' not in out


def test_main_raises_path_error_for_missing_config(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        'sys.argv',
        [
            'capex',
            '--devices',
            str(tmp_path / 'missing.yaml'),
            '--attacks',
            str(tmp_path / 'also-missing.yaml'),
            '--dry-run',
        ],
    )

    with pytest.raises(PathError, match='Devices config not found'):
        cli.main()


def test_main_runs_capture_session_only_for_enabled_devices(tmp_path, monkeypatch) -> None:
    devices_path, attacks_path = _write_configs(tmp_path)

    run_calls = []

    class _FakeCaptureSession:
        def __init__(self, *, runner, config) -> None:
            pass

        def run(self, *, device, attacks) -> None:
            run_calls.append(device.name)

    monkeypatch.setattr(cli, 'CaptureSession', _FakeCaptureSession)
    monkeypatch.setattr(
        'sys.argv',
        [
            'capex',
            '--devices',
            str(devices_path),
            '--attacks',
            str(attacks_path),
            '--output-dir',
            str(tmp_path / 'raw'),
            '--log-dir',
            str(tmp_path / 'logs'),
        ],
    )

    exit_code = cli.main()

    assert exit_code == 0
    assert run_calls == ['dev1']
